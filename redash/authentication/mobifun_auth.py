import logging
from flask import redirect, url_for, Blueprint, flash, request, session
from redash.authentication import oauth


from redash import models, settings
from redash.authentication import create_and_login_user, logout_and_redirect_to_index
from redash.authentication.org_resolving import current_org

logger = logging.getLogger('mobifun_auth')

blueprint = Blueprint('mobifun_auth', __name__)


def fetch_remote_token():
    return session['auth_token']


def register_remote_app():
    oauth.register('redash',
                     client_id='WAm_WlYsp-YlN6_3gxWWG2WY-FWLHrm1',
                     client_secret='qDItuJDJxiXEJU-kKDJDo03rjb7QKQtX',
                     access_token_url='https://portal.mobifun365.com/oauth-2/token',
                     access_token_params=None,
                     refresh_token_url=None,
                     authorize_url='https://portal.mobifun365.com/oauth-2/auth',
                     api_base_url='https://portal.mobifun365.com/',
                     client_kwargs={'scope': 'profile'},
                     fetch_token=fetch_remote_token,
    )
    return oauth.redash


@blueprint.route('/<org_slug>/oauth/redash', endpoint="authorize_org")
def org_login(org_slug):
    session['org_slug'] = current_org.slug
    return redirect(url_for(".authorize", next=request.args.get('next', None)))


@blueprint.route('/oauth/redash', endpoint="authorize")
def login():
    redirect_uri = url_for('.callback', _external=True)
    return register_remote_app().authorize_redirect(redirect_uri)


@blueprint.route('/oauth/redash_callback', endpoint="callback")
def authorized():
    access_token = register_remote_app().authorize_access_token()

    if access_token is None:
        logger.warning("Access token missing in call back request.")
        flash("Validation error. Please retry.")
        return redirect(url_for('redash.login'))

    session['auth_token'] = access_token
    session['auth_token']['token_type'] = 'Bearer'
    session['auth_token']['expires_in'] = 3600

    return redirect(url_for('.profile', _external=True))


@blueprint.route('/oauth/get_profile', endpoint="profile")
def app_profile():
    resp = register_remote_app().get('oauth-2/resource')
    profile = resp.json()

    picture_url = "%s?sz=40" % profile['picture']
    user = create_and_login_user(current_org, profile['name'], profile['email'], picture_url)
    if user is None:
        return logout_and_redirect_to_index()

    # next_path = request.args.get('state') or url_for("redash.index", org_slug=org.slug)
    next_path = request.args.get('state') or url_for("redash.index")

    return redirect(next_path)


