import os
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, constr

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set in .env")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in .env")

# BUG FIX: Neon requires SSL. If your DATABASE_URL is missing
# "?sslmode=require", connecting can hang or fail with an unhelpful error.
# This doesn't change your string, just fails fast with a clear message
# instead of a confusing hang, which is likely what you were seeing from
# Swagger UI.
if "neon.tech" in DATABASE_URL and "sslmode" not in DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL points to Neon but is missing '?sslmode=require'. "
        "Add it to your .env, e.g. "
        "postgresql://user:pass@host/db?sslmode=require"
    )

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# BUG FIX: previously any string (including empty "") was accepted for
# username/password, since Pydantic only checked the type was `str`.
# constr enforces a minimum length so /register can't create junk accounts.
class Registration(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=50)
    password: constr(min_length=1, max_length=200)

class Posts(BaseModel):
    content: constr(strip_whitespace=True, min_length=1, max_length=2000)


def get_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
    except psycopg2.OperationalError as e:
        # BUG FIX: previously an unreachable/misconfigured DB raised a raw
        # 500 with no useful message. This surfaces a clearer error instead
        # of a silent hang/timeout in Swagger.
        raise HTTPException(
            status_code=503,
            detail=f"Could not connect to database: {e}"
        )
    cursor = conn.cursor()
    return conn, cursor


def get_current_user(authorization: str):
    try:
        parts = authorization.split(" ")

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="Invalid authorization header"
            )

        token = parts[1]

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("user_id")

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return user_id

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


@app.post("/register")
def register(users: Registration):
    conn, cursor = get_db()

    try:
        hashed_password = pwd_context.hash(users.password)

        cursor.execute(
            """
            INSERT INTO users (username, password)
            VALUES (%s, %s)
            """,
            (users.username, hashed_password)
        )

        conn.commit()

        return {
            "message": "user registered :)"
        }

    except psycopg2.IntegrityError:
        conn.rollback()

        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )

    finally:
        cursor.close()
        conn.close()


@app.post("/login")
def login(users: Registration):
    conn, cursor = get_db()

    try:
        cursor.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = %s
            """,
            (users.username,)
        )

        db_user = cursor.fetchone()

        if db_user is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid Credentials"
            )

        if not pwd_context.verify(
            users.password,
            db_user[2]
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid Credentials"
            )

        token = jwt.encode(
            {
                "user_id": db_user[0],
                "username": db_user[1],
                "exp": datetime.now(timezone.utc) + timedelta(days=1)
            },
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        return {
            "token": token
        }

    finally:
        cursor.close()
        conn.close()


@app.post("/posts")
def create_post(
    posts: Posts,
    authorization: str = Header(...)
):
    user_id = get_current_user(authorization)

    conn, cursor = get_db()

    try:
        cursor.execute(
            """
            INSERT INTO posts (content, user_id)
            VALUES (%s, %s)
            """,
            (posts.content, user_id)
        )

        conn.commit()

        return {
            "message": "post created"
        }

    finally:
        cursor.close()
        conn.close()


@app.get("/posts")
def show_post():
    conn, cursor = get_db()

    try:
        cursor.execute(
            """
            SELECT
                posts.id,
                posts.content,
                users.username,
                COUNT(likes.user_id) AS like_count
            FROM posts
            JOIN users
                ON posts.user_id = users.id
            LEFT JOIN likes
                ON posts.id = likes.post_id
            GROUP BY
                posts.id,
                posts.content,
                users.username
            ORDER BY posts.id DESC
            """
        )

        show = cursor.fetchall()

        return [
            {
                "id": row[0],
                "content": row[1],
                "username": row[2],
                "likes": row[3]
            }
            for row in show
        ]

    finally:
        cursor.close()
        conn.close()


@app.delete("/post/{id}")
def delete_post(
    id: int,
    authorization: str = Header(...)
):
    user_id = get_current_user(authorization)

    conn, cursor = get_db()

    try:
        cursor.execute(
            "DELETE FROM posts WHERE id = %s AND user_id = %s",
            (id, user_id)
        )

        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Post not found or you are not the owner"
            )

        return {
            "message": "post deleted"
        }

    except psycopg2.errors.ForeignKeyViolation:
        # BUG FIX: if `likes` references posts without ON DELETE CASCADE,
        # deleting a post that has likes throws a raw FK violation and the
        # old code returned an unhandled 500 ("Delete failed." in the UI
        # with no explanation). This surfaces a clear, actionable message.
        # Proper fix: run this once against your DB (see notes below):
        #   ALTER TABLE likes
        #   DROP CONSTRAINT likes_post_id_fkey,
        #   ADD CONSTRAINT likes_post_id_fkey
        #     FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE;
        conn.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Cannot delete: this post still has likes referencing it. "
                "Add ON DELETE CASCADE to the likes.post_id foreign key."
            )
        )

    finally:
        cursor.close()
        conn.close()


@app.post("/post/{id}/like")
def like_post(
    id: int,
    authorization: str = Header(...)
):
    user_id = get_current_user(authorization)

    conn, cursor = get_db()

    try:
        cursor.execute(
            """
            SELECT 1 FROM posts WHERE id = %s
            """,
            (id,)
        )
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Post not found")

        cursor.execute(
            """
            INSERT INTO likes (post_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT (post_id, user_id)
            DO NOTHING
            """,
            (id, user_id)
        )

        conn.commit()

        return {
            "message": "post is liked"
        }

    except psycopg2.errors.InvalidColumnReference:
        # BUG FIX: ON CONFLICT (post_id, user_id) needs a matching UNIQUE
        # constraint on the likes table. Without it every like request
        # throws this error and previously just 500'd with no explanation.
        # Fix once in your DB:
        #   ALTER TABLE likes ADD CONSTRAINT likes_post_user_unique
        #     UNIQUE (post_id, user_id);
        conn.rollback()
        raise HTTPException(
            status_code=500,
            detail=(
                "likes table is missing a UNIQUE(post_id, user_id) "
                "constraint required for ON CONFLICT to work."
            )
        )

    finally:
        cursor.close()
        conn.close()


@app.delete("/post/{id}/like")
def delete_like(
    id: int,
    authorization: str = Header(...)
):
    user_id = get_current_user(authorization)

    conn, cursor = get_db()

    try:
        cursor.execute(
            """
            DELETE FROM likes
            WHERE post_id = %s
            AND user_id = %s
            """,
            (id, user_id)
        )

        conn.commit()

        return {
            "message": "post like is deleted"
        }

    finally:
        cursor.close()
        conn.close()
