from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter
from flask_pass0.utils import login_required, get_current_user

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['PASS0_DEV_MODE'] = True

# Database setup
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    
    def to_dict(self):
        return {"id": self.id, "email": self.email}

# Routes
@app.route('/')
@login_required
def index():
    user = get_current_user()
    return render_template('index.html', user=user)

@app.route('/public')
def public():
    return '<h1>Public Page</h1><p>Anyone can see this. <a href="/auth/login">Login</a></p>'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Initialize storage and Pass0 inside app context
        storage = SQLAlchemyStorageAdapter(
            user_model=User,
            session=db.session,
            secret_key=app.config['SECRET_KEY']
        )
        pass0 = Pass0(app, storage_adapter=storage)
    
    app.run(debug=True)