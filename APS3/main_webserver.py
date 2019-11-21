from pymongo import MongoClient

client = MongoClient()

client = MongoClient("mongodb://localhost:27017/")

mydb = client['name_of_database']

mycolletion = mydb['my_table']

json = {
    'title': 'titulo',
    'description': 'description',
    'done': False
}

#INSERT
res = mydb.my_table.insert(json) 

#GET
for i in mydb.myTable.find({'title': 'MongoDB and Python'}):
    print(i) 

#COUNT
print(mydb.myTable.count({'title': 'MongoDB and Python'})) 
