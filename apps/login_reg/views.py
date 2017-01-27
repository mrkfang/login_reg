from django.shortcuts import render, redirect
from django.contrib import messages
from . import models
import re, bcrypt

def index(request):

    # data =  models.User.objects.all()
    # context = { "datas": data }
    # models.User.objects.filter(id = 4).delete()
    # return render(request, "login_reg/index.html", context)
    return render(request, "login_reg/index.html")

def register(request):

    first_name = request.POST['first_name']
    last_name = request.POST['last_name']
    user_email = request.POST['email']
    user_pass = request.POST['password']

    valid = True

    email_list = models.User.objects.filter(email = user_email)
    if email_list:
        messages.add_message(request, messages.WARNING, 'Email already exists')
        valid = False
    if len(first_name) < 2 or len(last_name) < 2:
        messages.add_message(request, messages.WARNING, 'Your first/last name is too short')
        valid = False
    if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", user_email):
        messages.add_message(request, messages.WARNING, 'Please enter valid Email format')
        valid = False
    if len(user_pass) < 8:
        messages.add_message(request, messages.WARNING, 'Password must be at least 8 letters')
        valid = False
    if user_pass != request.POST['confirm_password']:
        messages.add_message(request, messages.WARNING, 'Password does not match')
        valid = False
    if valid:
        hashed = bcrypt.hashpw(str(user_pass), bcrypt.gensalt())
        models.User.objects.create(first_name= first_name, last_name= last_name, email= user_email, password=hashed)
        return render(request, "login_reg/success.html")
    return redirect("/")

def login(request):
    # if bcrypt.hashpw(password, hashed) == hashed:
    user_email = request.POST['email']
    user_pass = request.POST['password'].encode()

    valid = True

    email_list = models.User.objects.filter(email = user_email)
    if not email_list:
        messages.add_message(request, messages.WARNING, 'Invalid Email or Password')
        valid = False
    if email_list:
        if not bcrypt.hashpw(user_pass, email_list[0].password.encode()) == email_list[0].password.encode():
            # print email_list[0].password
            valid = False
            messages.add_message(request, messages.WARNING, 'Invalid Email or Password')
    if valid:
        request.session['user_id'] = models.User.objects.filter(email = user_email)[0].id
        return redirect("/success")
    else:
        return redirect("/")

def success(request):
    if not 'user_id' in request.session: # if nothing in session, redirect to index.html
        return redirect("/")
    return render(request, "login_reg/success.html")

def logout(request):
    if "user_id" in request.session:
        request.session.pop('user_id')
    return redirect("/")
