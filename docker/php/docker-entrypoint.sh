#!/bin/bash
set -e

until nc -z mariadb 3306 2>/dev/null; do
    echo "Waiting for MariaDB..."
    sleep 2
done

if ! wp core is-installed --allow-root 2>/dev/null; then
    echo "Installing WordPress with admin/admin..."
    wp core install \
        --url="http://localhost" \
        --title="WP Secure" \
        --admin_user="admin" \
        --admin_password="admin" \
        --admin_email="admin@localhost.local" \
        --allow-root
    echo "WordPress installed."
fi

exec docker-php-entrypoint php-fpm
