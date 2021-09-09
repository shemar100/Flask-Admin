from my_app import app
app.env="development"
#app.run(debug=True, ssl_context='adhoc')
app.run(host='127.0.0.1',port=4455,debug=True)