FROM php:8.2-cli

WORKDIR /app
COPY . /app

# Install dependencies for SQLite
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev \
    && docker-php-ext-install pdo pdo_sqlite

# Render assigns the PORT environment variable dynamically
CMD php -S 0.0.0.0:$PORT index.php
