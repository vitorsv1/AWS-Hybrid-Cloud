#!flask/bin/python

from flask import Flask, jsonify, abort, make_response
from flask_restful import Api, Resource, reqparse, fields, marshal
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__, static_url_path="")
api = Api(app)
auth = HTTPBasicAuth()

@auth.get_password
def get_password(username): 
    if username == 'vitor':
        return 'python'
    return None

@auth.error_handler
def unauthorized():
    #Return 403 for personalize message
    return make_response(jsonify({'message': 'Unauthorized access'}), 403)

tasks = [
    {
        'id': 1,
        'title': u'Color',
        'description': u'Red, Blue, White, Green',
        'done': False
    },
    {
        'id': 2,
        'title': u'IPO',
        'description': u'PETR4, FLRY3, ITSA4, IBOV11, HGLG11, XPLG11',
        'done': False
    }
]

task_fields = {
    'title': fields.String,
    'description': fields.String,
    'done': fields.Boolean,
    'url': fields.Url('task')
}

class TaskList(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('title', type=str, required=True,
                                   help='No task title provided',
                                   location='json')
        self.reqparse.add_argument('description', type=str, default="",
                                   location='json')
        super(TaskList, self).__init__()

    def get(self):
        return {'tasks': [marshal(task, task_fields) for task in tasks]}

    def post(self):
        args = self.reqparse.parse_args()
        task = {
            'id': tasks[-1]['id'] + 1 if len(tasks) > 0 else 1,
            'title': args['title'],
            'description': args['description'],
            'done': False
        }
        tasks.append(task)
        return {'task': marshal(task, task_fields)}, 201


class Task(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('title', type=str, location='json')
        self.reqparse.add_argument('description', type=str, location='json')
        self.reqparse.add_argument('done', type=bool, location='json')
        super(Task, self).__init__()

    def get(self, id):
        #Checkar o ID
        task = [task for task in tasks if task['id'] == id]
        if len(task) == 0:
            abort(404)
        
        return {'task': marshal(task[0], task_fields)}

    def put(self, id):
        #Checkar o ID
        task = [task for task in tasks if task['id'] == id]
        if len(task) == 0:
            abort(404)

        task = task[0]
        args = self.reqparse.parse_args()
        for k, v in args.items():
            if v is not None:
                task[k] = v
        return {'task': marshal(task, task_fields)}

    def delete(self, id):
        task = [task for task in tasks if task['id'] == id]
        if len(task) == 0:
            abort(404)
        tasks.remove(task[0])
        return {'result': True}

class TaskHealth(Resource):

    def get(self):
        return 200


api.add_resource(TaskList, '/Tarefa', endpoint='tasks')
api.add_resource(Task, '/Tarefa/<int:id>', endpoint='task')
api.add_resource(TaskHealth, '/healthcheck', endpoint='taskhealth')

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
