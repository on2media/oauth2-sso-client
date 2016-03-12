<?php

namespace On2Media\OAuth2SSO;

class Client
{
    private $config = [];

    private $oAuth2Provider;

    private $localStorage;

    private $eventListener;

    public function __construct(
        array $config,
        LocalStorage $localStorage = null,
        EventListener $eventListener = null
    ) {
        $this->config = $config;
        $this->oAuth2Provider = new \League\OAuth2\Client\Provider\GenericProvider(
            [
                'clientId' => $config['client_id'],
                'clientSecret' => $config['client_secret'],
                'urlAuthorize' => $config['authorize_url'],
                'urlAccessToken' => $config['access_token_url'],
                'urlResourceOwnerDetails' => $config['resource_owner_details_url'],
            ]
        );

        $this->localStorage = ($localStorage === null ? new LocalStorage() : $localStorage);
        $this->eventListener = ($eventListener === null ? new EventListener() : $eventListener);
    }

    public function buildSignInUrl()
    {
        return $this->buildAuthUrl($this->config['sso_sign_in_url']);
    }

    private function buildAuthUrl($url)
    {
        list($timeMid, $timeLow) = explode(' ', microtime());
        $nonce = dechex($timeLow) . sprintf('%04x', (int) substr($timeMid, 2) & 0xffff);
        $hash = hash_hmac(
            'sha1',
            $this->config['client_id'] . $nonce,
            $this->config['client_secret']
        );

        return $url . '?' . http_build_query(
            [
                'sso' => '1',
                'client' => $this->config['client_id'],
                'nonce' => $nonce,
                'hash' => $hash,
            ]
        );
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

    public function handleCallback()
    {
        if (empty($_GET['state']) || $_GET['state'] !== $this->localStorage->getOAuth2State()) {
            $this->localStorage->unsetOAuth2State();
            throw new Exception('Invalid or missing state');
        }

        $this->localStorage->unsetOAuth2State();

        if (isset($_GET['error'])) {
            throw new Exception(
                'Unexpected error, ' . $_GET['error'] . ': ' . $_GET['error_description']
            );
        }

        if (!isset($_GET['code'])) {
            throw new Exception('No authorisation code');
        }

        try {

            $accessToken = $this->oAuth2Provider->getAccessToken(
                'authorization_code',
                [
                    'code' => $_GET['code'],
                ]
            );

            $resourceOwner = $this->oAuth2Provider->getResourceOwner($accessToken);

            $this->localStorage->setAuth(
                new Authorisation(
                    $accessToken->getToken(),
                    $accessToken->getRefreshToken(),
                    $accessToken->getExpires(),
                    $resourceOwner->toArray()
                )
            );

        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

            $this->eventListener->failedSignIn();

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $this->config['sign_in_url']);
            exit;

        }
    }

    public function checkSignedIn()
    {
        if (!$this->localStorage->getAuth()) {

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $this->config['authenticate_url']);
            exit;

        }

        if ($this->localStorage->getAuth()->getExpires() < time()) {

            try {

                $newAccessToken = $this->oAuth2Provider->getAccessToken(
                    'refresh_token',
                    [
                        'refresh_token' => $this->localStorage->getAuth()->getRefreshToken()
                    ]
                );

            } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

                $this->localStorage->unsetAuth();

                if ($e->getMessage() != 'invalid_grant') {
                    throw $e;
                }

                $this->eventListener->sessionClosed();
                header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
                header('Location: ' . $this->config['authenticate_url']);
                exit;

            }

            $this->localStorage->getAuth()->setAccessToken($newAccessToken->getToken());
            $this->localStorage->getAuth()->setExpires($newAccessToken->getExpires());

        }

        try {

            $accessToken = new \League\OAuth2\Client\Token\AccessToken(
                [
                    'access_token' => $this->localStorage->getAuth()->getAccessToken(),
                ]
            );

            $resourceOwner = $this->oAuth2Provider->getResourceOwner($accessToken);

        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

            if ($e->getMessage() != 'invalid_token' && $e->getMessage() != 'expired_token') {
                throw $e;
            }

            $this->eventListener->sessionClosed();

            // the access token has prematurely expired due to inactivity
            $this->localStorage->getAuth()->setExpires(0);

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . $this->config['authenticate_url']);
            exit;

        }
    }

    public function handleForceRefreshToken()
    {
        $this->localStorage->getAuth()->setExpires(0);

        header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
        header('Location: ' . $this->config['authenticate_url']);
        exit;
    }

    public function handleSignOut()
    {
        $this->localStorage->unsetAuth();
        $this->eventListener->signedOut();

        header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
        header('Location: ' . $this->buildAuthUrl($this->config['sso_sign_out_url']));
        exit;
    }
}
