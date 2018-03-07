<?php
namespace PsgcLaravelPackages\AccessControl;

use Closure;

// %TODO: scrap this and try to go with only Entrust (!)
// See: 
// ~ => https://laravel.com/docs/5.6/authentication#protecting-routes
// ~ https://laravel.com/docs/5.6/authorization
// ~ https://github.com/Zizaco/entrust
// ~ https://stackoverflow.com/questions/33439193/in-laravel-should-i-check-for-permission-in-controller-if-already-checking-on-m?rq=1
// ~ https://github.com/spatie/laravel-authorize
abstract class AccessManager
{

    // %REQUIRES: User model implement ->roles attribute (eg, relations)
    // %REQUIRES: User model implement ->username // %TODO: make a function so it's generic returns some kind of GUID, or a GUID
    //
    protected $_sessionUser = null;
    protected $_superadminRoles = []; // roles that override access matrix checking

    abstract protected function accessMatrix(); 

    // Optional: override in child class to add superadmin roles
    protected function setSuperadminRoles();
    {
        $this->_superadminRoles = []; // default is none
    }

    public function handle($request, Closure $next)
    {
        // Before middleware here

        // Assumes a user is logged in: this takes care of the 'auth' part of the middleware
        if ( \Auth::guest() ) {
            \App::abort(403, 'Unauthorized action.');
            //return \Redirect::route('login');
        }
        $this->setSuperadminRoles();

        $this->_sessionUser = $sessionUser = \Auth::user();
        $roles = $sessionUser->roles;

        $isSuperadmin = false; // default
        foreach ($roles as $userRole) {
            // Check if session user has a superadmin role...
            if ( in_array($userRole,$this->_superadminRoles) ) {
                $isSuperadmin = true;
                break;
            }
        }

        if ( !$isSuperadmin ) {
            // Not a super admin, so use access matrix
            $accessMatrix = $this->accessMatrix();
    
            //$tmp = $request->route()->parameters();
            //dd($tmp);
            //dd($tmp->parameters());
            //dd($request->route('contractors'));
            //$slug = $request->slug; //  get parameter from request (eg slug)
            //$route = $request->route;
            $route = $request->route()->getName();
            $routeParams = $request->route()->parameters(); // for HTTP only not for AJAX
            $queryParams = \Input::all();
    
            //dd($route);
            //dd('This is the route ' . $route, $accessMatrix);
            $accessLevel = null; // Default is to deny access
            foreach ($roles as $role) {
            if ( array_key_exists($route,$accessMatrix) ) {
                    $accessLevel = !empty($accessMatrix[$route][$role->name]) ? $accessMatrix[$route][$role->name] : null; // find the function to call
                    //dd('here' . $accessLevel);
                    break;
    
                }
            }
    
            // If we get through the case statement without aborting, access is allowed
            if ( is_callable($accessLevel) ) {
                $isAllowed = $accessLevel($sessionUser,$routeParams,$queryParams); // call function
            } else {
                switch ($accessLevel) {
                    case 'all':
                        $isAllowed = true; // continue => grant access
                        break;
                    default:
                        $isAllowed = false;
                }
            }
            //dd($route,$sessionUser->email,$accessLevel,$role->name,$roles->toArray());
            if (!$isAllowed) {
                $jsonStr = json_encode(['route'=>$route,'user'=>$sessionUser->username,'roles'=>$roles]);
                \App::abort(403, 'Unauthorized action for role: '.$jsonStr);
            }
            // else allowed, return....
        }

        return $next($request);
    }
    
    
    
}
