<?php
namespace PsgcLaravelPackages\AccessControl;

use Closure;

abstract class AccessManager
{
    // %REQUIRES: User model implement ->roles attribute (eg, relations)
    // %REQUIRES: User model implement ->username // %TODO: make a function so it's generic returns some kind of GUID, or a GUID

    protected $_sessionUser = null;
    protected $_superadminRoles = []; // roles that override access matrix checking
    protected $_accessMatrix = [];

    abstract protected function accessMatrix(); 

    // Optional: override in child class to add superadmin roles
    protected function setSuperadminRoles()
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
        $this->setSuperadminRoles(); // must be first!!
        $this->_sessionUser = $sessionUser = \Auth::user();

        if ( $this->isSuperadmin($sessionUser) ) {

            $isAllowed = true;

        } else {

            // Not a super admin, so use access matrix
            $this->_accessMatrix = $this->accessMatrix();
    
            // === Parse request ===

            $requestAttrs = [
                'routename'   => $request->route()->getName(),
                'routeparams' => $request->route()->parameters(),
                'queryparams' => $request->all(),
            ];
            $isOK = preg_match("/(\w+)\.(\w+)\.(\w+)/", $requestAttrs['routename'], $matches); // parse route, eg 'api.widgets.store'
            if ( !$isOK || !is_array($matches) || (4>count($matches)) ) {
                throw new \Exception('Malformed route :'.$requestAttrs['routename'].', must be formatted {prefix}.{resource}.{action}');
            }
            $routePrefix   = $matches[1]; // eg 'api'
            $routeResource = $matches[2]; // eg 'widgets'
            $routeAction   = $matches[3]; // eg 'store'
    
            // === Find matching routes in access matrix ===
            // 3 possibilities:
            //    ~ exact           --  eg: api.widgets.update
            //    ~ wildcard_action --  eg: api.widgets.*
            //    ~ TBD: wildcard_resource --  eg: api.*.index

            $matchingRoutes = []; // keys
            if ( array_key_exists($requestAttrs['routename'],$this->_accessMatrix) ) {
                $matchingRoutes['exact'] = $requestAttrs['routename']; // exact match
            }
            $wildcardActionRoute = implode('.',[$routePrefix,$routeResource,'*']);
            if ( array_key_exists($wildcardActionRoute,$this->_accessMatrix) ) {
                $matchingRoutes['wildcard_action'] = $wildcardActionRoute; // eg api.widgets.*
            }

            // === Do the check (set $isAllowed) ===

            $isAllowed = false; // init: default is to deny access

            // find access check scalar or delegate function/closure
            if ( array_key_exists('exact',$matchingRoutes) ) {
                $isAllowed = $this->isAllowed($matchingRoutes['exact'],$requestAttrs); // 1st priority
            } else if ( array_key_exists('wildcard_action',$matchingRoutes) ) {
                $isAllowed = $this->isAllowed($matchingRoutes['wildcard_action'],$requestAttrs); // 2nd priority
            }
        }

        if (!$isAllowed) {
            $jsonStr = json_encode(['route'=>$requestAttrs['routename'],'user'=>$sessionUser->username,'roles'=>$sessionUser->roles]);
            \App::abort(403, 'Unauthorized action for role: '.$jsonStr);
        }

        return $next($request); // ...else allowed, return

    } // handle()
    

    // uses $this->_accessMatrix, // $this->_sessionUser
    protected function isAllowed($matrixKey,$requestAttrs) // matrixKey is route 'name', either exact or a wildcard variant
    {
        // HERE: determine if *any* role of this user allows access by its rules for this route

        $isAllowed = false;

        foreach ($this->_sessionUser->roles as $r) {

            if ( array_key_exists($matrixKey,$this->_accessMatrix) ) {
                $accessCheckDelegate = !empty($this->_accessMatrix[$matrixKey][$r->name]) ? $this->_accessMatrix[$matrixKey][$r->name] : null; // find the function to cll
                //$isAllowed = $this->isAllowed($this->_sessionUser,$requestAttrs['routeparams'],$requestAttrs['queryparams'],$accessCheckDelegate);
                if ( empty($accessCheckDelegate) ) {
                    $isAllowed = false;
                } else if ( is_callable($accessCheckDelegate) ) {
                    // Callable delegate
                    $isAllowed = call_user_func_array($accessCheckDelegate,[$this->_sessionUser,$requestAttrs['routeparams'],$requestAttrs['queryparams']]); // call function
                } else { // %FIXME: check that it's a string?
                    // Scalar : If we get through the case statement without aborting, access is allowed
                    switch ($accessCheckDelegate) {
                        case 'all':
                            $isAllowed = true; // continue => grant access
                            break;
                        default:
                            $isAllowed = false;
                    } // switch()
                }
                if ($isAllowed) {
                    break; // found one that allows access %TODO: be sure this breaks for loop not just if clause
                } // ...otherwise keep searching
            }

        } // foreach()

        return $isAllowed;

    } // isAllowed()

    protected function isSuperadmin($sessionUser)
    {
        $is = false; // default
        foreach ($sessionUser->roles as $r) {
            // Check if session user has a superadmin role...
            if ( in_array($r->name,$this->_superadminRoles) ) {
                $is = true;
                break;
            }
        }
        return $is;
    }
    
    
}

// See: 
// ~ => https://laravel.com/docs/5.6/authentication#protecting-routes
// ~ https://laravel.com/docs/5.6/authorization
// ~ https://github.com/Zizaco/entrust
// ~ https://stackoverflow.com/questions/33439193/in-laravel-should-i-check-for-permission-in-controller-if-already-checking-on-m?rq=1
// ~ https://github.com/spatie/laravel-authorize

/*
//$tmp = $request->route()->parameters();
//dd($tmp);
//dd($tmp->parameters());
//dd($request->route('contractors'));
//$slug = $request->slug; //  get parameter from request (eg slug)
//$route = $request->route;
//dd($route,$sessionUser->email,$accessLevel,$role->name,$sessionUser->roles->pluck('name'));
//dd($route);
 */
            /*
            //dd('This is the route ' . $requestAttrs['routename'], $accessMatrix);
            $accessCheckDelegate = null; // Default is to deny access
            foreach ($sessionUser->roles as $r) { // %FIXME: BUG this will only check the first role it finds assoc w/ the user (write test to expose)
                if ( array_key_exists($requestAttrs['routename'],$accessMatrix) ) {
                    $accessCheckDelegate = !empty($accessMatrix[$requestAttrs['routename']][$r->name]) ? $accessMatrix[$requestAttrs['routename']][$r->name] : null; // find the function to cll
                    break;
                }
            }
             */
