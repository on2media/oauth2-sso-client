<?php

namespace On2Media\OAuth2SSOClient;

class Provider extends \League\OAuth2\Client\Provider\GenericProvider
{
    private $keepTimeout = false;

    public function setKeepTimeout(bool $value)
    {
        $this->keepTimeout = $value;
    }

    protected function getDefaultHeaders()
    {
        if ($this->keepTimeout === true) {
            return [
                'Keep-Timeout' => '1',
            ];
        }
        return [];
    }
}
