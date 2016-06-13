from bottle import template

def mainpage():
    return template('mainpage')

def mainpage():
    with open('html/mainpage.html', 'r') as htmlfile:
        html = htmlfile.read()
        return html
