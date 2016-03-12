<?php

namespace On2Media\OAuth2SSOClient;

class Authorisation
{
    private $accessToken;

    private $refreshToken;

    private $expires;

    private $resourceOwner = [];

    public function __construct($accessToken, $refreshToken, $expires, array $resourceOwner)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->expires = $expires;
        $this->resourceOwner = $resourceOwner;
    }

    public function setAccessToken($value)
    {
        $this->accessToken = $value;
        return $this;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    public function setExpires($value)
    {
        $this->expires = $value;
        return $this;
    }

    public function getExpires()
    {
        return $this->expires;
    }

    public function getResourceOwner()
    {
        return $this->resourceOwner;
    }
}
