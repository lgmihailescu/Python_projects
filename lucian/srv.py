import hashlib
import string
from flask import Flask, request, render_template
import shlex, subprocess
import sys

app = Flask(__name__)
app.debug = True





@app.route('/')
def hello():
    print "Hello World!"

@app.route('/zone/<str:zone_id>/dns',methods=['POST'])
def rqdata():
    print zone_id + " : " + request.data

app.run(host='0.0.0.0')
