-- SQL script to create tables for the Art Gallery application.
-- This is equivalent to what `flask initdb` would generate.

-- Users table to store buyers, artists, and admins.
CREATE TABLE users (
    id INTEGER NOT NULL AUTO_INCREMENT,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20),
    created_at DATETIME,
    PRIMARY KEY (id),
    UNIQUE (username),
    UNIQUE (email)
);

-- Artworks table to store artwork details.
CREATE TABLE artworks (
    id INTEGER NOT NULL AUTO_INCREMENT,
    artist_id INTEGER NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    price NUMERIC(10, 2) NOT NULL,
    category VARCHAR(50) NOT NULL,
    image_path VARCHAR(255) NOT NULL,
    upload_date DATETIME,
    PRIMARY KEY (id),
    FOREIGN KEY(artist_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Orders table to store customer order information.
CREATE TABLE orders (
    id INTEGER NOT NULL AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    order_date DATETIME,
    total_amount NUMERIC(10, 2) NOT NULL,
    status VARCHAR(50) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Reviews table for artwork ratings and comments.
CREATE TABLE reviews (
    id INTEGER NOT NULL AUTO_INCREMENT,
    artwork_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER,
    comment TEXT,
    review_date DATETIME,
    PRIMARY KEY (id),
    FOREIGN KEY(artwork_id) REFERENCES artworks (id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Cart Items table to store items in a user's shopping cart.
CREATE TABLE cart_items (
    id INTEGER NOT NULL AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    artwork_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    date_added DATETIME,
    PRIMARY KEY (id),
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY(artwork_id) REFERENCES artworks (id)
);

-- Order Items table to link artworks to a specific order.
-- This acts as a junction table for the many-to-many relationship between orders and artworks.
CREATE TABLE order_items (
    id INTEGER NOT NULL AUTO_INCREMENT,
    order_id INTEGER NOT NULL,
    artwork_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price_at_purchase NUMERIC(10, 2) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(order_id) REFERENCES orders (id) ON DELETE CASCADE,
    FOREIGN KEY(artwork_id) REFERENCES artworks (id)
);
