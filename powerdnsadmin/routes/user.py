import datetime
import hashlib
import imghdr
import mimetypes
import json
from flask import Blueprint, request, render_template, make_response, jsonify, redirect, url_for, g, session, \
    current_app, after_this_request, abort
from flask_login import current_user, login_required, login_manager
from ..decorators import user_create_domain
from ..models.user import User, Anonymous
from ..models.setting import Setting
from ..models.api_key import ApiKey
from ..models.role import Role
from ..models.domain import Domain
from ..models.history import History
from ..models.account_user import AccountUser
from ..lib.errors import ApiKeyCreateFail
from ..models.base import db
from ..models.account import Account
from ..models.api_key_account import ApiKeyAccount
from .index import password_policy_check
from ..lib.schema import ApiPlainKeySchema
from base64 import b64encode
apikey_plain_schema = ApiPlainKeySchema(many=True)

user_bp = Blueprint('user',
                    __name__,
                    template_folder='templates',
                    url_prefix='/user')


@user_bp.before_request
def before_request():
    # Check if user is anonymous
    g.user = current_user
    login_manager.anonymous_user = Anonymous

    # Check site is in maintenance mode
    maintenance = Setting().get('maintenance')
    if maintenance and current_user.is_authenticated and current_user.role.name not in [
            'Administrator', 'Operator'
    ]:
        return render_template('maintenance.html')

    # Manage session timeout
    session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(
        minutes=int(Setting().get('session_timeout')))
    session.modified = True

    # Clean up expired sessions in the database
    if Setting().get('session_type') == 'sqlalchemy':
        from ..models.sessions import Sessions
        Sessions().clean_up_expired_sessions()


@user_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        return render_template('user_profile.html')
    if request.method == 'POST':
        if session['authentication_type'] == 'LOCAL':
            firstname = request.form.get('firstname', '').strip()
            lastname = request.form.get('lastname', '').strip()
            email = request.form.get('email', '').strip()
            new_password = request.form.get('password', '')
        else:
            firstname = lastname = email = new_password = ''
            current_app.logger.warning(
                'Authenticated externally. User {0} information will not allowed to update the profile'
                .format(current_user.username))

        if request.data:
            jdata = request.json
            data = jdata['data']
            if jdata['action'] == 'enable_otp':
                if session['authentication_type'] in ['LOCAL', 'LDAP']:
                    enable_otp = data['enable_otp']
                    user = User(username=current_user.username)
                    user.update_profile(enable_otp=enable_otp)
                    return make_response(
                        jsonify({
                            'status':
                            'ok',
                            'msg':
                            'Change OTP Authentication successfully. Status: {0}'
                            .format(enable_otp)
                        }), 200)
                else:
                    return make_response(
                        jsonify({
                            'status':
                            'error',
                            'msg':
                            'User {0} is externally. You are not allowed to update the OTP'
                            .format(current_user.username)
                        }), 400)

        (password_policy_pass, password_policy) = password_policy_check(current_user.get_user_info_by_username(), new_password)
        if not password_policy_pass:
            if request.data:
                return make_response(
                    jsonify({
                        'status': 'error',
                        'msg': password_policy['password'],
                    }), 400)
            return render_template('user_profile.html', error_messages=password_policy)

        user = User(username=current_user.username,
                    plain_text_password=new_password,
                    firstname=firstname,
                    lastname=lastname,
                    email=email,
                    reload_info=False)

        user.update_profile()

        return render_template('user_profile.html')
    
@user_bp.route('/user-manage-keys', methods=['GET', 'POST'])
@login_required
@user_create_domain
def user_manage_keys():
    if request.method == 'GET':
        try:
            apikeys = db.session.query(ApiKey) \
                .join(ApiKeyAccount, ApiKeyAccount.apikey_id == ApiKey.id) \
                .join(AccountUser, ApiKeyAccount.account_id == AccountUser.account_id) \
                .filter(AccountUser.user_id == current_user.id) \
                .all()
        except Exception as e:
            current_app.logger.error('Error: {0}'.format(e))
            abort(500)

        return render_template('user_manage_keys.html',
                               keys=apikeys)
@user_bp.route('/key/edit/<key_id>', methods=['GET'])
@login_required
@user_create_domain
def edit_key(key_id=None):
    apikey = None
    create = True
    plain_key = None
    if key_id:
        apikey = ApiKey.query.filter(ApiKey.id == key_id).first()
        create = False
        if not apikey:
            return render_template('errors/404.html'), 404
    if request.method == 'GET':
        try:
            apikey.update(key=key_id)
            plain_key = apikey_plain_schema.dump([apikey])[0]["plain_key"]
            print(plain_key)
            plain_key = b64encode(plain_key.encode('utf-8')).decode('utf-8')
            apikey.key_view = plain_key
            try:
                apikey.update() 
            except Exception as e:
                current_app.logger.error('Error updating ApiKey: {0}'.format(e))
                raise ApiKeyCreateFail(message='Failed to save key_view')
            history_message = "Updated API key {0}".format(apikey.id)
        except Exception as e:
            current_app.logger.error('Error: {0}'.format(e))
         

        history = History(msg=history_message,
                          detail=json.dumps({
                              'key': apikey.id,
                              'role': apikey.role.name,
                              'description': apikey.description,
                              'domains': [domain.name for domain in apikey.domains],
                              'accounts': [a.name for a in apikey.accounts]
                          }),
                          created_by=current_user.username)
        history.add()
        
        try:
            apikeys = db.session.query(ApiKey) \
                .join(ApiKeyAccount, ApiKeyAccount.apikey_id == ApiKey.id) \
                .join(AccountUser, ApiKeyAccount.account_id == AccountUser.account_id) \
                .filter(AccountUser.user_id == current_user.id) \
                .all()
        except Exception as e:
            current_app.logger.error('Error: {0}'.format(e))
            abort(500)
        return render_template('user_manage_keys.html',
                               keys=apikeys,
                               create=create,
                               plain_key=plain_key)

@user_bp.route('/user-guide', methods=['GET', 'POST'])
@login_required
@user_create_domain
def user_guide():
    return render_template('user_guide.html')
               
@user_bp.route('/qrcode')
@login_required
def qrcode():
    if not current_user:
        return redirect(url_for('index'))

    return current_user.get_qrcode_value(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@user_bp.route('/image', methods=['GET'])
@login_required
def image():
    """Returns the user profile image or avatar."""

    @after_this_request
    def add_cache_headers(response_):
        """When the response is ok, add cache headers."""
        if 200 <= response_.status_code <= 399:
            response_.cache_control.private = True
            response_.cache_control.max_age = int(datetime.timedelta(days=1).total_seconds())
        return response_

    def return_image(content, content_type=None):
        """Return the given binary image content. Guess the type if not given."""
        if not content_type:
            guess = mimetypes.guess_type('example.' + imghdr.what(None, h=content))
            if guess and guess[0]:
                content_type = guess[0]

        return content, 200, {'Content-Type': content_type}

    # To prevent "cache poisoning", the username query parameter is required
    if request.args.get('username', None) != current_user.username:
        abort(400)

    setting = Setting()

    if session['authentication_type'] == 'LDAP':
        search_filter = '(&({0}={1}){2})'.format(setting.get('ldap_filter_username'),
                                                 current_user.username,
                                                 setting.get('ldap_filter_basic'))
        result = User().ldap_search(search_filter, setting.get('ldap_base_dn'))
        if result and result[0] and result[0][0] and result[0][0][1]:
            user_obj = result[0][0][1]
            for key in ['jpegPhoto', 'thumbnailPhoto']:
                if key in user_obj and user_obj[key] and user_obj[key][0]:
                    current_app.logger.debug(f'Return {key} from ldap as user image')
                    return return_image(user_obj[key][0])

    email = current_user.email
    if email and setting.get('gravatar_enabled'):
        hash_ = hashlib.md5(email.encode('utf-8')).hexdigest()
        url = f'https://s.gravatar.com/avatar/{hash_}?s=100'
        current_app.logger.debug('Redirect user image request to gravatar')
        return redirect(url, 307)

    # Fallback to the local default image
    return current_app.send_static_file('img/user_image.png')
