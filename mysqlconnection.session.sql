-- In your MySQL client
-- This script will completely reset your database.
-- WARNING: This is a destructive operation. Use with caution.
-- To reset, uncomment the two lines below.
-- DROP DATABASE IF EXISTS art_gallery_db;
-- CREATE DATABASE art_gallery_db;
USE art_gallery_db;

-- --- FIX FOR THIS ERROR ---
-- If you are seeing an "Unknown column 'created_at'" error, it means your database is out of sync.
-- Run the following command in your MySQL client to add the missing column without losing data:
-- ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- --- FIX FOR RATING NULLABILITY ERROR ---
-- If you are seeing an "Column 'rating' cannot be null" error, it means your database schema is out of sync.
-- Run the following command in your MySQL client to allow reviews without a star rating:
-- ALTER TABLE reviews MODIFY COLUMN rating INT NULL;

-- Use plural table names to match the SQLAlchemy models in app.py
CREATE TABLE users (
    id INT AUTO_INCREMENT,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'buyer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE artworks (
    id INT AUTO_INCREMENT,
    artist_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50) NOT NULL,
    image_path VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (artist_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE order_items (
    id INT AUTO_INCREMENT,
    order_id INT NOT NULL,
    artwork_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    price_at_purchase DECIMAL(10, 2) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    -- It's often better not to cascade delete on artwork, so an order history remains
    -- even if an artwork is removed from the store. The app logic handles this.
    FOREIGN KEY (artwork_id) REFERENCES artworks(id)
);

CREATE TABLE reviews (
    id INT AUTO_INCREMENT,
    artwork_id INT NOT NULL,
    user_id INT NOT NULL,
    rating INT,
    comment TEXT,
    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (artwork_id) REFERENCES artworks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE cart_items (
    id INT AUTO_INCREMENT,
    user_id INT NOT NULL,
    artwork_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (artwork_id) REFERENCES artworks(id) ON DELETE SET NULL
);
INSERT INTO artworks (
    id,
    artist_id,
    title,
    description,
    price,
    category,
    image_path,
    upload_date
  )
VALUES (
    id:int,
    artist_id:int,
    'title:varchar',
    'description:text',
    'price:decimal',
    'category:varchar',
    'image_path:varchar',
    'upload_date:timestamp'
  );