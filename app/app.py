from flask import Flask, request, make_response, jsonify
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from dotenv import load_dotenv
import os
from model import db, User, Product, Order, Cart, CartItem, Contact
from datetime import timedelta


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False
load_dotenv()
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)


migrate = Migrate(app, db)
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)
CORS(app, resources={r"/*": {"origins": "*"}})

class Login(Resource):
    def post(self):
        email = request.json.get("email")
        password = request.json.get("password")

        if not email or not password:
            return {"error": "Email and password are required"}, 400

        user = User.query.filter_by(email=email).first()

        if user is None:
            return {"error": "Email not found"}, 404

        if not bcrypt(user.password, password):
            return {"error": "Incorrect password"}, 401

        # Check the role of the user
        if user.role == 'admin':
            access_token = create_access_token(identity={"id": user.id, "email": email, "role": "admin"})
            return {"access_token": access_token, "role": "admin"}, 200
        else:
            access_token = create_access_token(identity={"id": user.id, "email": email, "role": user.role})
            return {"access_token": access_token, "role": user.role}, 200

api.add_resource(Login, '/login')

class SignUp(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return{"error": "Ensure that both the email and password are filled"}
        
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email = email).first()

        if not user:
            return {"error": "user does not exist"}
        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "password is incorrect"}, 401
        
        access_token = create_access_token(identity={'id': user.id, 'role': user.role})
        refresh_token = create_refresh_token(identity={'id': user.id, 'role': user.role})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(SignUp, '/signup')

class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500
        
api.add_resource(TokenRefresh, '/tokenrefresh')


class UserResource(Resource):
    @jwt_required()
    def get(self):
        claims = get_jwt_identity()
        if claims['role']  != 'admin':
            return {"error": "you are not authorized to get this information"}, 403
        
        users = [user.to_dict() for user in User.query.all()]
        return make_response(users, 200)
    
    @jwt_required
    def post(self):
        claims = get_jwt_identity
        if claims['role'] != 'admin':
            return{"error": "you are not authorized to carry out this action"}, 403
        
        data = request.get_json()
        if not data:
            return {"error": "all fields need to be filled"}, 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).deocde('uft-8')
        user = User(
            name =data['name'],
            email=data['email'],
            role = data['role'],
            password = hashed_password,
            department = data['department'],
        )

        db.session.add(user)
        db.session.commit()
        return make_response(user.to_dict(), 201)
    
api.add_resource(UserResource, '/user')


class UserById(Resource):
    def get(self, id):
        user = User.query.filter_by(id=id).first()
        if user is None:
            return {"error": "User not found"}, 404
        response_dict = user.to_dict()
        return make_response(response_dict, 200)

    def patch(self, id):
        user = User.query.filter_by(id=id).first()
        if user is None:
            return {"error": "User not found"}, 404

        data = request.get_json()
        if all(key in data for key in ['name', 'email', 'password']):
            try:
                user.name = data['name']
                user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
                user.email = data['email']

                db.session.commit()
                return make_response(user.to_dict(), 200)
            except Exception as e:
                return {"error": str(e)}, 500
        else:
            return {"error": "Missing required fields: name, email, and password"}, 400
            
api.add_resource(UserById, '/user/<int:id>')


class OrderResource(Resource):
    @jwt_required()
    def get(self):
        claims = get_jwt_identity()
        if claims['role'] != 'admin' or 'employee':
           return {'error': "you are not authorized to get this information"},403
        
        order = [order.to_dict() for order in Order.query.all()]
        return make_response(order, 200)
        

    def post(self):
        data = request.get_json()
        required_keys = ['user_name', 'amount', 'date', 'status', 'payment_method', 'address']
        if not all(key in data for key in required_keys):
            return jsonify({"error": "Ensure all fields are filled"}), 400

        try:
            order = Order(
                user_name=data['user_name'],
                amount=data['amount'],
                date=data['date'],
                status=data['status'],
                payment_method=data['payment_method'],
                address=data['address'],
            )

            db.session.add(order)
            db.session.commit()
            return make_response(order.to_dict(), 201)
        
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
    

api.add_resource(OrderResource, '/order')

class ProductResource(Resource):
    def get(self):
        product = [product.to_dict() for product in Product.query.all()]
        return make_response(product, 200)


    @jwt_required 
    def post(self):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'error': "you are not authorized to create a product"}, 403
        data = request.get_json()
        if not data:
            return{"error": "all fields need to be filled"}, 400
        
        product = Product(
            name=data['name'],
            price=data['price'],
            description=data['description'],
            stock=data['stock'],
            category =data['category'],
            image = data['image']
        )

        db.session.add(product)
        db.session.commit()
        return make_response(product.to_dict(), 201)
    
api.add_resource(ProductResource, '/product')

class ProductById(Resource):
    def get(self, id):
        product = Product.query.filter_by_id(id=id).first()
        if not product:
            return{"error":"product not found"},404
        response_dict = product.to_dict()
        return make_response(response_dict, 200)

    @jwt_required()
    def patch(self, id):
        claims = get_jwt_identity
        if claims['role'] != 'admin' or "employee":
            return{"error": "you are not authorized to carry out this task"},403
        
        product = Product.query.filter_by(id=id).first()
        if product is None:
            return {"error": "User not found"}, 404
        
        data = request.get_json()
        if all (key in data for key in ['name', 'category', 'price', 'image', 'stock','decription']):
            try: 
                product.name = data['name']
                product.category = data['category']
                product.price = data['price']
                product.image = data['image']
                product.stock = data['stock']
                product.description = data['description']

                db.session.commit()
                return make_response(product.to_dict(), 200)
            except Exception as e:
                return {"error": str(e)}, 500
        else:
            return {"error": "Missing required fields: name, category, price, image, stock and description"}, 400
            

        

    @jwt_required()
    def delete(self, id):
        claims = get_jwt_identity
        if claims['role'] != "admin" or "employee":
            return{"error": "you are not authorized to carry out this task"}, 403
        product = Product.query.get(id)
        if product is None:
            return{"error": "product not found"}, 404
        
        db.session.delete(product)
        db.session.commit()

        return jsonify({'message': 'Product sucessfully deleted'})
        
api.add_resource(ProductById, '/product/<int:id>')

class ProductByCategory(Resource):
    def get(self, category):
        product = Product.query.filter_by_category(category = category).first()
        if not Product:
            return{"error": "category is not found"}, 404
        
        response_dict = product.to_dict()
        return make_response(response_dict, 200)
    
api.add_resource(ProductByCategory, '/product/<str:category>')
    
class ProductByName(Resource):
    def get(self, name):
        product = Product.query.filter_by(name=name).first()
        if not product:
            return {"error": "product not found"}, 404
        
        response_dict= product.to_dict()
        return make_response(response_dict, 200)
    
api.add_resource(ProductByName, '/product/<str:name>')

class CartResource(Resource):
    def get(self):
        cart = [Cart.to_dict() for cart in Cart.query.all()]
        return make_response(cart, 200)

api.add_resource(CartResource, '/cart')

class CartItemResource(Resource):
    def post(self, id):
        data = request.get_json()
        required_keys = ['quantity', 'product_id', 'cart_id']
        if not all(key in data for key in required_keys):
            return jsonify({"error": "Ensure all fields are filled"}), 400

        try:
            cartitem = CartItem(
                quantity=data['quantity'],
                product_id=data['product_id'],
                cart_id=data['cart_id']
            )

            db.session.add(cartitem)
            db.session.commit()
            return make_response(cartitem.to_dict(), 201)
        
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    def patch(self, id):
        pass

    def delete(self, id):
        product = Product.query.get(id)
        if product is None:
            return {"error": "product not found"}, 404
        
        db.session.delete(product)
        db.session.commit()

        return jsonify({'message': 'Product sucessfully deleted'})

api.add_resource(CartItemResource, '/cartitem')

class Contact(Resource):
    def post(self):
        pass

    @jwt_required()
    def get(self):
        claims = get_jwt_identity()
        if claims['role'] not in ['admin', 'employee']:
            return {"error": "You are not authorized to get this information"}, 403
        
        contacts = [contact.to_dict() for contact in Contact.query.all()]
        return make_response(jsonify(contacts), 200)
    
api.add_resource(Contact,'/contact')









if __name__ == '__main__':
    app.run(debug=True, port=5500)




