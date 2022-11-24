<?php

namespace RistekUSDI\Keycloak\Token\Laravel;

use Illuminate\Support\Facades\Auth;
use RistekUSDI\Keycloak\Token\Laravel\Auth\UserProvider;
use RistekUSDI\Keycloak\Token\Laravel\Auth\Guard\TokenGuard;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Default
        $this->publishes([
            // Config
            __DIR__ . '/../config/keycloak-token.php' => config_path('keycloak-token.php'),
        ], 'keycloak-token-laravel-config');

        Auth::provider('keycloak-token', function($app, array $config) {
            return new UserProvider($config['model']);
        });
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        Auth::extend('keycloak-token', function ($app, $name, array $config) {
            return new TokenGuard(Auth::createUserProvider($config['provider']), $app->request);
        });

        // Auth middleware
        $this->app['router']->middlewareGroup('keycloak-token.authenticate', [
            \RistekUSDI\Keycloak\Token\Laravel\Middleware\Authenticate::class,
        ]);

        // Client role middleware
        $this->app['router']->aliasMiddleware('keycloak-token.client-role', 
            \RistekUSDI\Keycloak\Token\Laravel\Middleware\ClientRole::class
        );
    }
}
