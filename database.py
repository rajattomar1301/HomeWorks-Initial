from peewee import *
db = SqliteDatabase("dev.db")

class BaseModel(Model):
	class Meta:
		database = db


class User(BaseModel):
	name = CharField()
	email = CharField()
	password = CharField()
	isATeacher = BooleanField(default=False)
	standard = CharField()
	section = CharField()
	school = CharField()
	conf_key = CharField()
	emailconf = BooleanField(default=False)
	firstsociallogin = BooleanField(default=True)

class HomeWork(BaseModel):
	name = CharField()
	description = TextField()
	filename = CharField()
	originalname = CharField()
	teacher = IntegerField()
	teachername = CharField()
	deadline = CharField()
	meantfor = CharField()
	meantforsection = CharField()
	subject = CharField()

class HomeWorkSubmission(BaseModel):
	student = IntegerField()
	time = CharField()
	marks = IntegerField()
	homework = IntegerField()
	filename1 = CharField()
	originalfilename1 = CharField()

class Submitted(BaseModel):
	homework = IntegerField()
	student = IntegerField()


