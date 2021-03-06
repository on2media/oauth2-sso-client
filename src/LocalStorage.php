<?php

namespace On2Media\OAuth2SSOClient;

class LocalStorage
{
    public function setOAuth2State($value)
    {
        $_SESSION['oauth2state'] = $value;
        return $this;
    }

    public function unsetOAuth2State()
    {
        unset($_SESSION['oauth2state']);
        return $this;
    }

    public function getOAuth2State()
    {
        if (isset($_SESSION['oauth2state'])) {
            return $_SESSION['oauth2state'];
        }
        return null;
    }

    public function setAuth(Authorisation $value)
    {
        $_SESSION['auth'] = $value;
        return $this;
    }

    public function unsetAuth()
    {
        unset($_SESSION['auth']);
        return $this;
    }

    public function getAuth()
    {
        if (isset($_SESSION['auth'])) {
            return $_SESSION['auth'];
        }
        return null;
    }

    public function setReturnUrl($value)
    {
        $_SESSION['return_url'] = $value;
        return $this;
    }

    public function unsetReturnUrl()
    {
        unset($_SESSION['return_url']);
        return $this;
    }

    public function getReturnUrl()
    {
        if (isset($_SESSION['return_url'])) {
            return $_SESSION['return_url'];
        }
        return null;
    }
}
