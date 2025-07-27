from flask import Flask, request, send_file, jsonify

app = Flask(__name__)


@app.route('/image.png', methods=['GET'])
def download_file():
    ip_address = request.remote_addr
    query_string = request.query_string.decode()
    print(f'IP: {ip_address} - Query: {query_string}')

    return send_file('image.png', as_attachment=True)


@app.errorhandler(404)
def page_not_found(e):
    return jsonify(error=str(e)), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
