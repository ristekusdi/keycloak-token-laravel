<?php

namespace RistekUSDI\Keycloak\Token\Laravel\Auth\Guard;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use RistekUSDI\Keycloak\Token\Laravel\Token;
use RistekUSDI\Keycloak\Token\Laravel\Exceptions\KeycloakException;

class TokenGuard implements Guard
{
    private $config;
    private $user;
    private $provider;
    private $decodedToken;
    private Request $request;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->config = config('keycloak-token');
        $this->user = null;
        $this->provider = $provider;
        $this->decodedToken = null;
        $this->request = $request;

        $this->authenticate();
    }

    /**
     * Decode token, validate and authenticate user
     *
     * @return mixed
     */
    private function authenticate()
    {
        try {
            $this->decodedToken = Token::decode($this->request->bearerToken(), $this->config['realm_public_key'], $this->config['leeway']);
        } catch (\Exception $e) {
            throw new KeycloakException($e->getMessage());
        }

        if ($this->decodedToken) {
            $this->validate((array) $this->decodedToken);
        }
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (is_null($this->user)) {
            return null;
        }
        
        if ($this->config['append_decoded_token']) {
            $this->user->token = $this->decodedToken;
        }
        
        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        if ($this->user()) {
            return $this->user()->id;
        }
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return mixed
     */
    public function validate(array $credentials = [])
    {
        if (!$this->decodedToken) {
            return false;
        }
        
        $this->validateResources();
        
        if ($this->config['load_user_from_database']) {
            $methodOnProvider = $this->config['user_provider_custom_retrieve_method'] ?? null;
            if ($methodOnProvider) {
                $user = $this->provider->{$methodOnProvider}($this->decodedToken, $credentials);
            } else {
                $user = $this->provider->retrieveByCredentials($credentials);
            }      

            if (!$user) {
                throw new KeycloakException("User not found. Credentials: " . json_encode($credentials), 404);
            }
        } else {
            $user = $this->provider->retrieveByCredentials($credentials);
        }
        
        $this->setUser($user);
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return self
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        return $this;
    }

    /**
     * Validate if authenticated user has a valid resource
     *
     * @return void
     */
    private function validateResources()
    {
        $token_resource_access = array_keys((array)($this->decodedToken->resource_access ?? []));
        $allowed_resources = explode(',', $this->config['allowed_resources']);
        if (count(array_intersect($token_resource_access, $allowed_resources)) == 0) {
            throw new KeycloakException("The decoded JWT token has not a valid `resource_access` allowed by API. Allowed resources by API: " . $this->config['allowed_resources'], 403);
        }
    }

    /**
     * Returns full decoded JWT token from authenticated user
     *
     * @return mixed|null
     */
    public function token()
    {
        return json_encode($this->decodedToken);
    }

    /**
     * Check if authenticated user has a especific role into resource
     * @param string $roles
     * @param string $resource
     * @return bool
     */
    public function hasRole($roles = array(), $resource = '')
    {
        $token_resource_access = (array) $this->decodedToken->resource_access;
        if (array_key_exists($resource, $token_resource_access)) {
            $resource_access = (array) $token_resource_access[$resource];
            $resource_roles = $resource_access['roles'];
            
            return (array_intersect($roles, $resource_roles)) ? true : false;
        } else {
            return false;
        }
    }
}
