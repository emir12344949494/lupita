from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from pymongo import MongoClient
import hashlib
from bson import ObjectId
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

client = MongoClient('mongodb+srv://23300080:%40Zagc050205@citla.onqkm4j.mongodb.net/bd1')
db = client.bd1
usuarios_collection = db.usuarios
archivos_criticos_collection = db.archivos_criticos

bcrypt = Bcrypt(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(min=2, max=20)])
    apellido = StringField('Apellido', validators=[DataRequired(), Length(min=2, max=20)])
    genero = StringField('Género', validators=[DataRequired()])
    correo = StringField('Correo', validators=[DataRequired(), Email()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    confirmar_contraseña = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('contraseña',
                                                                                                     message='Las contraseñas deben coincidir')])
    submit = SubmitField('Registrarse')

class LoginForm(FlaskForm):
    correo = StringField('Correo', validators=[DataRequired(), Email()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegistrationForm()
    if form.validate_on_submit():
        nombre = form.nombre.data
        apellido = form.apellido.data
        genero = form.genero.data
        correo = form.correo.data
        contraseña = form.contraseña.data
        contraseña_cifrada = bcrypt.generate_password_hash(contraseña).decode('utf-8')
        usuarios_collection.insert_one({
            'nombre': nombre,
            'apellido': apellido,
            'genero': genero,
            'correo': correo,
            'contraseña': contraseña_cifrada
        })
        flash('Registro exitoso', 'success')
        return redirect(url_for('index'))
    return render_template('registro.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        correo = form.correo.data
        contraseña = form.contraseña.data
        user = usuarios_collection.find_one({'correo': correo})
        if user and bcrypt.check_password_hash(user['contraseña'], contraseña):
            session['user_id'] = str(user['_id'])
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('index'))
        else:
            flash('Correo o contraseña incorrectos', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))


@app.route('/monitor', methods=['GET', 'POST'])
@login_required
def monitor():
    if request.method == 'POST':
        nombre_archivo = request.form['nombre_archivo']
        contenido = request.form['contenido']
        algoritmo = request.form['algoritmo']
        fecha_hora_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if algoritmo == 'SHA128':
            hash_func = hashlib.sha1
        elif algoritmo == 'SHA256':
            hash_func = hashlib.sha256
        elif algoritmo == 'SHA512':
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha256

        hash_obj = hash_func()
        hash_obj.update((nombre_archivo + contenido + fecha_hora_actual).encode('utf-8'))
        hash_value = hash_obj.hexdigest()

        archivo = archivos_criticos_collection.find_one({'nombre_archivo': nombre_archivo, 'user_id': session['user_id']})
        if archivo:
            # Verificar si el archivo ha cambiado
            estado = 'No editado'
            if hash_value != archivo['hash']:
                estado = 'Editado'
                archivos_criticos_collection.update_one({'_id': archivo['_id']}, {
                    '$set': {
                        'contenido': contenido,
                        'algoritmo': algoritmo,
                        'fecha_hora': fecha_hora_actual,
                        'hash': hash_value
                    }
                })
            else:
                flash('No se detectaron cambios.', 'info')
        else:
            archivos_criticos_collection.insert_one({
                'nombre_archivo': nombre_archivo,
                'contenido': contenido,
                'algoritmo': algoritmo,
                'fecha_hora': fecha_hora_actual,
                'hash': hash_value,
                'user_id': session['user_id']
            })
            estado = 'Nuevo'

        flash('Archivo crítico registrado o actualizado exitosamente.', 'success')

    archivos = list(archivos_criticos_collection.find({'user_id': session['user_id']}))
    for archivo in archivos:
        archivo['existing_hash'] = archivo['hash']
        archivo['hash_dividido'] = [archivo['hash'][i:i+30] for i in range(0, len(archivo['hash']), 30)]
        # Asignar el estado
        archivo['status'] = 'Editado' if archivo['hash'] != archivo['existing_hash'] else 'No editado'

    return render_template('monitor.html', archivos=archivos)

@app.route('/edit/<file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    archivo = archivos_criticos_collection.find_one({'_id': ObjectId(file_id)})
    if request.method == 'POST':
        nombre_archivo = request.form['nombre_archivo']
        contenido = request.form['contenido']
        algoritmo = request.form['algoritmo']
        fecha_hora_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if algoritmo == 'SHA128':
            hash_func = hashlib.sha1
        elif algoritmo == 'SHA256':
            hash_func = hashlib.sha256
        elif algoritmo == 'SHA512':
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha256

        hash_obj = hash_func()
        hash_obj.update((nombre_archivo + contenido + fecha_hora_actual).encode('utf-8'))
        hash_value = hash_obj.hexdigest()

        if hash_value != archivo['hash']:
            archivos_criticos_collection.update_one({'_id': ObjectId(file_id)}, {
                '$set': {
                    'nombre_archivo': nombre_archivo,
                    'contenido': contenido,
                    'algoritmo': algoritmo,
                    'fecha_hora': fecha_hora_actual,
                    'hash': hash_value,
                    'estado': 'editado'  # Actualizar el estado a 'editado'
                }
            })
            flash('Archivo actualizado exitosamente.', 'success')
        else:
            flash('No se detectaron cambios.', 'info')

        return redirect(url_for('monitor'))

    return render_template('edit_file.html', archivo=archivo)

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    archivos_criticos_collection.delete_one({'_id': ObjectId(file_id)})
    flash('Archivo eliminado exitosamente.', 'success')
    return redirect(url_for('monitor'))

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8090)




