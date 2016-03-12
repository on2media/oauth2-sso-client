<?php

namespace On2Media\OAuth2SSO;

class LocalStorage
{
    public static function setOAuth2State($value)
    {
        $_SESSION['oauth2state'] = $value;
        // return $this;
    }

    public static function unsetOAuth2State()
    {
        unset($_SESSION['oauth2state']);
        // return $this;
    }

    public static function getOAuth2State()
    {
        if (isset($_SESSION['oauth2state'])) {
            return $_SESSION['oauth2state'];
        }
        return null;
    }

    public static function setAuth(Authorisation $value)
    {
        $_SESSION['auth'] = $value;
        // return $this;
    }

    public static function unsetAuth()
    {
        unset($_SESSION['auth']);
        // return $this;
    }

    public static function getAuth()
    {
        if (isset($_SESSION['auth'])) {
            return $_SESSION['auth'];
        }
        return null;
    }
}
