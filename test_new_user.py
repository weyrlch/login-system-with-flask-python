from app import app, db, User
from sqlalchemy import text

# Crie um contexto de aplicativo antes de adicionar o usuário
with app.app_context():
    user = User(username="nicolas", email="nicolas@test.com")
    user.set_password("123456")
    db.session.add(user)
    db.session.commit()

    print("User added successfully!")
