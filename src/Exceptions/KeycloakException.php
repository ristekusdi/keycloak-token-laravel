<?php
namespace RistekUSDI\Keycloak\Token\Laravel\Exceptions;

class KeycloakException extends \UnexpectedValueException
{
    public function __construct(string $message, int $code = 401)
    {
        $this->message = "[Keycloak Exception] {$message}";
        $this->code = $code;
    }
}