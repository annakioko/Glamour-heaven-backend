from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
import re
from enum import Enum
from sqlalchemy import CheckConstraint

db = SQLAlchemy()

class User(db, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    image = db.Column(db.String)
    role = db.Column(db.String, nullable=False, default='User')
    department = db.Column(db.String, default='N/A')
    address = db.Column(db.String, default='N/A')

    carts = db.relationship('Carts', back_populates='user')
    orders = db.relationship("Order", back_populates="user")


    @validates('email')
    def validates_email(self, key, email):
       assert '@' in email
       assert re.match(r"[^@]+@[^@]+\.[^@]+", email), "Invalid email format"
       return email
    
    @validates('password')
    def validates_password(self, key, password):
        assert len(password) > 8
        assert re.search(r"[A-Z]", password), "Password should contain at least one uppercase letter"
        assert re.search(r"[a-z]", password), "Password should contain at least one lowercase letter"
        assert re.search(r"[0-9]", password), "Password should contain at least one digit"
        assert re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Password should contain at least one special character"
        return password
    
    def __repr__(self):
        return f"<{self.id}, {self.name}, {self.email},{self.password}, {self.image}, {self.role}, 
        {self.department}, {self.address} >"

class Product(db, SerializerMixin):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    category = db.Column(db.String)
    price = db.Column(db.Float)
    image = db.Column(db.String, nullable = False)
    stock = db.Column(db.Float)
    description = db.Column(db.String)

    cartitems = db.relationship("Cartitems", back_populates = "products")

    @validates('description')
    def validate_description(self, key, description):
        if not 5 <= len(description) <= 150:
           raise ValueError("Description must be between 5 and 100 characters.")
        return description


    @validates('category')
    def validates_category(self, key, category):
        allowed_categories = ['Beard Gang', 'Skin care', 'Gift and Packages', 'Haircare', 'Makeup', 'Fragrances']
        if category not in allowed_categories:
           raise ValueError ("the category is not part of the categories we have in store")
        return category

    def __repr__(self):
        return f"<Product {self.id}, {self.name}, {self.stock}, {self.category}, {self.description}, {self.price}, {self.price} >"


class Cart(db, SerializerMixin):
    __tablename__ = 'carts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    users = db.relationship('User', backref=db.backref('cart', uselist=False))

    def __repr__(self):
        return f"<Cart {self.id}, User {self.user_id}>"

class CartItem(db, SerializerMixin):
    __tablename__ = 'cartitems'

    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('carts.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    product = db.relationship('Product', backref=db.backref('cart_items'))
    cart = db.relationship('Cart', backref=db.backref('items', cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<CartItem {self.id}, Cart {self.cart_id}, Product {self.product_id}, Quantity {self.quantity}>"

class Order(db, SerializerMixin):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String)
    payment_method = db.Column(db.String)
    status = db.Column(db.String, default='pending')
    date = db.Column(db.DateTime)
    amount = db.Column(db.Float)
    user_name = db.Column(db.String, db.ForeignKey('users.name')) 

    user = db.relationship("User", back_populates="orders", foreign_keys=[user_name])



    def __repr__(self):
        return f"<Order {self.id}, {self.address}, {self.payment_method}, {self.status}, {self.date}, {self.amount}>"
    


    #relationships with each model
    #user has a one to one relation with cart
    #user has a one to many relation with order
    #cart has a one to many realtion with cart items
    #products has a many to many relationship with cart items 