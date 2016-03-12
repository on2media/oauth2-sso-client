<?php

namespace On2Media\OAuth2SSO;

class Client
{
    private $oAuth2Provider;

    private $eventListener;

    public function __construct(
        \League\OAuth2\Client\Provider\GenericProvider $oAuth2Provider,
        EventListener $eventListener
    ) {
        $this->oAuth2Provider = $oAuth2Provider;
        $this->eventListener = $eventListener;
    }

    public function getEventListener()
    {
        return $this->eventListener;
    }

    private static function getAuthenticateUrl()
    {
        return 'authenticate.php';
    }

    public static function getSignInUrl()
    {
        return 'sign-in.php';
    }

    public static function getHomeUrl()
    {
        return 'index.php';
    }

    public static function buildSignInUrl()
    {
        return self::buildAuthUrl(getenv('OAUTH2_URL_SSO_SIGN_IN'));
    }

    public static function buildSignOutUrl()
    {
        return self::buildAuthUrl(getenv('OAUTH2_URL_SSO_SIGN_OUT'));
    }

    private static function buildAuthUrl($url)
    {
        list($timeMid, $timeLow) = explode(' ', microtime());
        $nonce = dechex($timeLow) . sprintf('%04x', (int) substr($timeMid, 2) & 0xffff);
        $hash = hash_hmac(
            'sha1',
            getenv('OAUTH2_CLIENT_ID') . $nonce,
            getenv('OAUTH2_CLIENT_SECRET')
        );

        return $url . '?' . http_build_query(
            [
                'sso' => '1',
                'client' => getenv('OAUTH2_CLIENT_ID'),
                'nonce' => $nonce,
                'hash' => $hash,
            ]
        );
    }

    public function checkSignedIn()
    {
        if (!isset($_SESSION['auth'])) {

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . self::getAuthenticateUrl());
            exit;

        }

        if ($_SESSION['auth']['expires'] < time()) {

            try {

                $newAccessToken = $this->oAuth2Provider->getAccessToken(
                    'refresh_token',
                    [
                        'refresh_token' => $_SESSION['auth']['refresh_token']
                    ]
                );

            } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

                unset($_SESSION['auth']);

                if ($e->getMessage() != 'invalid_grant') {
                    throw $e;
                }

                $this->getEventListener()->sessionClosed();
                header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
                header('Location: ' . self::getAuthenticateUrl());
                exit;

            }

            $_SESSION['auth']['access_token'] = $newAccessToken->getToken();
            $_SESSION['auth']['expires'] = $newAccessToken->getExpires();

        }

        try {

            $accessToken = new \League\OAuth2\Client\Token\AccessToken(
                [
                    'access_token' => $_SESSION['auth']['access_token'],
                ]
            );

            $resourceOwner = $this->oAuth2Provider->getResourceOwner($accessToken);

        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

            if ($e->getMessage() != 'invalid_token' && $e->getMessage() != 'expired_token') {
                throw $e;
            }

            $this->getEventListener()->sessionClosed();

            // the access token has prematurely expired due to inactivity
            $_SESSION['auth']['expires'] = 0;

            header($_SERVER['SERVER_PROTOCOL'] . ' 302 Found');
            header('Location: ' . self::getAuthenticateUrl());
            exit;

        }
    }
}
