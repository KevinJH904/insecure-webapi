
import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson


def getToken():
    tiempo = datetime.now().timestamp()
    numero = random.random()
    cadena = str(tiempo) + str(numero)
    numero2 = random.random()
    cadena2 = str(numero)+str(tiempo)+str(numero2)
    m = hashlib.sha1()
    m.update(cadena.encode())
    P = m.hexdigest()
    m = hashlib.md5()
    m.update(cadena.encode())
    Q = m.hexdigest()
    return f"{P[:20]}{Q[20:]}"


@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')

    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}

    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                # FIXEO: SQL IJECTION
                'INSERT INTO Usuario values(null,%s,%s,md5(%s))',(request.json["uname"],request.json["email"],request.json["password"],)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e)
        return {"R": -2}
    return {"R": 0, "D": R}


@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}

    try:
        with db.cursor() as cursor:
            cursor.execute(
                # FIXEO: SQL INJECTION
                'SELECT id FROM Usuario WHERE uname= %s and password=md5(%s)',(request.json["uname"],request.json["password"],)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -3}

    T = getToken()

    with open("/tmp/log", "a") as log:
        log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
        log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')

    try:
        with db.cursor() as cursor:
            #FIXEO: SQL INJECTION
            cursor.execute('Delete from AccesoToken where id_Usuario= %s',(R[0][0],))
            cursor.execute('insert into AccesoToken values(%s,%s,now())',(R[0][0],T,))
            db.commit()
            db.close()
            return {"R": 0, "D": T}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -4}


@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()

    if not request.json:
        return {"R": -1}

    R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
    if not R:
        return {"R": -1}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    TKN = request.json['token']

    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token= %s',(TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    id_Usuario = R[0][0]

    with open(f'tmp/{id_Usuario}', "wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))

    try:
        with db.cursor() as cursor:
            #FIXEO: SQL INJECTION
            cursor.execute('INSERT INTO Imagen values(null,%s,"img/",%s)',(request.json["name"],id_Usuario,))
            cursor.execute('SELECT max(id) as idImagen FROM Imagen where id_Usuario= %s',(id_Usuario,))
            R = cursor.fetchall()
            idImagen = R[0][0]
            #FIXEO: SQL INJECTION
            #A = cursor.execute('update Imagen set ruta = "img/'+str(idImagen)+'.'+str(request.json['ext'])+'" where id = '+str(idImagen))
            A = cursor.execute("UPDATE Imagen set ruta=CONCAT('img/', %s, '.', %s) where id=%s",(idImagen,request.json['ext'],idImagen,))
            db.commit()
            shutil.move(f'tmp/{id_Usuario}', f'img/{idImagen}.{request.json["ext"]}')
            return {"R": 0, "D": A}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3,"RES":R}


@post('/Descargar')
def Descargar():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}

    R = 'token' in request.json and 'id' in request.json
    if not R:
        return {"R": -1}

    TKN = request.json['token']
    idImagen = request.json['id']

    try:
        with db.cursor() as cursor:
            # FIXEO: SQL IJECTION 
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token= %s',(TKN,))
            #cursor.execute('select id_Usuario from AccesoToken where token = "'+TKN+'"');
            R = cursor.fetchall()
            #return {"R": -401, "msg":R}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    try:
        with db.cursor() as cursor:
            # FIXEO3: Falta de validacion en las Credenciales se podia observar cualquier imagen Independietemente del Usuario 
            # Se restructura un poco el SQL para agregar la validacion que coincida con el id_Usuario
            cursor.execute('Select name,ruta FROM Imagen WHERE id = %s',(idImagen,))
            R = cursor.fetchall() 
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3,"Valor":R}



    print(Path("img").resolve(),R[0][1])
    return static_file(R[0][1], Path(".").resolve())


if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True)
