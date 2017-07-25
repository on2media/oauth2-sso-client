<?php

namespace On2Media\OAuth2SSOClient;

class Client extends ClientLite
{
    public function buildSignInUrl()
    {
        return $this->buildAuthUrl($this->config['sso_sign_in_url']);
    }

    public function handleAuthenticate()
    {
        if (!isset($_GET['success'])) {

            // it's the first time at this page, so check if the visitor is signed in at the provider

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $this->buildAuthUrl($this->config['sso_sign_in_url']));
            exit;

        } elseif ($_GET['success'] == 'true') {

            // we're signed in, so let's get a token

            $authorizationUrl = $this->oAuth2Provider->getAuthorizationUrl();
            $this->localStorage->setOAuth2State($this->oAuth2Provider->getState());

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $authorizationUrl);
            exit;

        }

        if (!isset($_GET['welcome'])) {

            // if `welcome` isn't set then a sign in attempt has been made
            $this->eventListener->failedSignIn();

        }

        // redirect to the sign in form

        header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
        header('Location: ' . $this->config['sign_in_url']);
        exit;
    }

    protected function fetchAuth($code)
    {
        try {

            parent::fetchAuth($code);

        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

            $this->eventListener->failedSignIn();

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $this->config['sign_in_url']);
            exit;

        }
    }

    protected function initAuthenticateState()
    {
        return $this->config['authenticate_url'];
    }
}
