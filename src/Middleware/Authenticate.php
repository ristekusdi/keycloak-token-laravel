<?php 

namespace RistekUSDI\Keycloak\Token\Laravel\Middleware;

use Closure;

class Authenticate {
	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request  $request
	 * @param  \Closure  $next
	 * @return mixed
	 */
	public function handle(\Illuminate\Http\Request $request, Closure $next)
	{
        try {
            $user = auth()->guard('keycloak-token')->user();
            if ($user !== null && $user instanceof \RistekUSDI\Keycloak\Token\Laravel\Models\User) {
                return $next($request);
            }
        } catch (\Throwable $th) {
			// Suppressing error for error message
			// InvalidArgumentException: The HTTP status code "0" is not valid.
            $code = ($th->getCode() !== 0) ? $th->getCode() : 500;
            return response()->json(['message' => $th->getMessage()], $code);
        }
	}

}