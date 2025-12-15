from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
import os
from src.models.models import MPesaUpload, db

from src.routes.utils import token_required

upload_bp = Blueprint("upload_bp", __name__, url_prefix="/upload")

@upload_bp.route("/screenshot", methods=["POST"])
@token_required
def upload_screenshot(current_user):
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    upload = Upload(filename=filename, user_id=current_user.id)
    db.session.add(upload)
    db.session.commit()
    return jsonify({"message": "File uploaded", "filename": filename})
