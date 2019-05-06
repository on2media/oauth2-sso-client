<?php

namespace On2Media\OAuth2SSOClient;

class ClientLite
{
    protected $config = [];

    protected $oAuth2Provider;

    protected $localStorage;

    protected $eventListener;

    protected $justTimedOut = false;

    public function __construct(
        array $config,
        LocalStorage $localStorage = null,
        EventListener $eventListener = null
    ) {
        $this->config = $config;
        $this->oAuth2Provider = new Provider(
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

    protected function buildAuthUrl($url)
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

        $this->fetchAuth($_GET['code']);
    }

    protected function fetchAuth($code)
    {
        $accessToken = $this->oAuth2Provider->getAccessToken(
            'authorization_code',
            [
                'code' => $code,
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
    }

    public function checkSignedIn($returnUrl = null)
    {
        if (!$this->isSignedIn($returnUrl)) {
            $this->redirectToAuthenticateUrl();
        }
    }

    public function isSignedIn($returnUrl = null, $keepTimeout = false)
    {
        $this->justTimedOut = false;

        if (!$this->localStorage->getAuth()) {

            $this->localStorage->setReturnUrl($returnUrl);
            return false;

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
                $this->localStorage->setReturnUrl($returnUrl);

                if ($e->getMessage() != 'invalid_grant') {
                    throw $e;
                }

                $this->eventListener->sessionClosed();
                $this->justTimedOut = true;
                return false;

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

            $this->oAuth2Provider->setKeepTimeout($keepTimeout);
            $resourceOwner = $this->oAuth2Provider->getResourceOwner($accessToken);
            $this->localStorage->getAuth()->setResourceOwner($resourceOwner->toArray());

        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

            if ($e->getMessage() != 'invalid_token' && $e->getMessage() != 'expired_token') {
                throw $e;
            }

            $this->eventListener->sessionClosed();
            $this->justTimedOut = true;

            // the access token has prematurely expired due to inactivity
            $this->localStorage->getAuth()->setExpires(0);
            $this->localStorage->setReturnUrl($returnUrl);

            return false;

        }

        return true;
    }

    public function handleForceRefreshToken($returnUrl = null)
    {
        $this->localStorage->getAuth()->setExpires(0);
        $this->localStorage->setReturnUrl($returnUrl);

        $this->redirectToAuthenticateUrl();
    }

    private function redirectToAuthenticateUrl()
    {
        $authenticateUrl = $this->initAuthenticateState();

        header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
        header('Location: ' . $authenticateUrl);
        exit;
    }

    protected function initAuthenticateState()
    {
        $authenticateUrl = $this->oAuth2Provider->getAuthorizationUrl();
        $this->localStorage->setOAuth2State($this->oAuth2Provider->getState());
        if ($this->justTimedOut === true) {
            $authenticateUrl .= '&just_timed_out=1';
            $this->justTimedOut = false;
        }
        return $authenticateUrl;
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
