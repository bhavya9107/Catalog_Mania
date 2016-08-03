import sys
from sqlalchemy import Column, ForeignKey, Integer,String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
Base = declarative_base()

class User(Base):
    __tablename__='user'
    name=Column(
        String(80), nullable=False
    )
    id=Column(
        Integer, primary_key = True
    )
    email=Column(
        String(80), nullable=False
    )
    picture = Column(String(250))
    
class Category(Base):
    __tablename__='category'
    name=Column(
        String(80), nullable=False
    )
    id=Column(
        Integer, primary_key = True
    )
    user=relationship(User)
    user_id=Column(
        Integer, ForeignKey('user.id')
    )
    
    @property
    def serialCat(self):
        return {
            'name':self.name,
            'id':self.id,
        }

class Item(Base):
    __tablename__='item'
    user=relationship(User)
    category= relationship(Category)
    name=Column(
        String(80),nullable= False
    )
    id=Column(
        Integer,primary_key= True
    )
    description= Column(
        String(250)
    )
    category_id= Column(
        Integer, ForeignKey('category.id')
    )
    user_id=Column(
        Integer, ForeignKey('user.id')
    )
    
    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description, 
            'id': self.id,
        }
    
#insert at the end of file
engine= create_engine(
    'sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)
print 'done'