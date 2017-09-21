from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Category, Base, Item

engine = create_engine('sqlite:///categories.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

category1 = Category(user_id=1, name="Music Mediums")

session.add(category1)
session.commit()

category2 = Category(user_id=1, name="Listening Devices")

session.add(category2)
session.commit()

category3 = Category(user_id=1, name="Instruments")

session.add(category3)
session.commit()

Item1 = Item(user_id=1, name="12 Vinyl", description="12 Vinyl Record",
             category_name="Music Mediums")

session.add(Item1)
session.commit()

Item2 = Item(user_id=1, name="Compact Disc",
             description="Compact disc (CD) is \
             a digital optical disc data storage format",
             category_name="Music Mediums")

session.add(Item2)
session.commit()

Item3 = Item(user_id=1, name="Loud Speaker",
             description="An electroacoustic transducer which converts \
             an electrical audio signal into a corresponding sound.",
             category_name="Listening Devices")

session.add(Item3)
session.commit()

Item4 = Item(user_id=1, name="Headphones",
             description="Headphones are electronic audio devices \
             that people wear over their ears.",
             category_name="Listening Devices")

session.add(Item4)
session.commit()

Item5 = Item(user_id=1, name="Guitar",
             description="The guitar is a musical instrument classified \
             as a fretted string instrument with anywhere from four to 18 \
             strings, usually having six.",
             category_name="Instruments")

session.add(Item5)
session.commit()

Item6 = Item(user_id=1, name="Drum Kit",
             description="A collection of drums and other percussion \
             instruments, typically cymbals, which are set up on stands \
             to be played by a single player",
             category_name="Instruments")

session.add(Item6)
session.commit()
