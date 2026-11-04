# Belvia API

Node.js + Express + Postgres (Neon).

## Environment variables (set them on your host, never in code)
- DATABASE_URL: your Neon connection string, including the password
- JWT_SECRET: a long random string
- FRONTEND_ORIGIN: the address where index.html is hosted (for example https://yoursite.example)

## Run
    npm install
    npm start

Tables are created automatically on first start.
If the connection fails with a channel binding error, remove `&channel_binding=require` from DATABASE_URL.
