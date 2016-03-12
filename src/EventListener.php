<?php

namespace On2Media\OAuth2SSO;

class EventListener
{
    public function failedSignIn()
    {
        $_SESSION['failed_sign_in'] = true;
    }

    public function signedOut()
    {
        $_SESSION['just_signed_out'] = true;
    }

    public function sessionClosed()
    {
        $_SESSION['timed_out'] = true;
    }
}
