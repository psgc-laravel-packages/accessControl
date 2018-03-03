<?php
namespace PsgcLaravelPackages\AccessControl;

use Closure;

class CheckAdmin
{
    public function handle($request, Closure $next)
    {
        // Before middleware here

        // Assumes a user is logged in
        if ( \Auth::guest() ) {
            \App::abort(403, 'Unauthorized action.');
        } 

        $user = \Auth::user();
        
        $isAllowed = $user->hasRole('newlogix-admin');

        if (!$isAllowed) {
            \App::abort(403, 'Unauthorized action.');
        }

        // %FIXME: do check
        return $next($request);
    }

}
