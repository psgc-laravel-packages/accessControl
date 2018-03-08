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
            $isAllowed = $this->isAllowed($matchingRoutes,$requestAttrs); // 2nd priority

        }

        if (!$isAllowed) {
            $jsonStr = json_encode(['route'=>$requestAttrs['routename'],'user'=>$sessionUser->username,'roles'=>$sessionUser->roles]);
            \App::abort(403, 'Unauthorized action for role: '.$jsonStr);
        }

        return $next($request); // ...else allowed, return

    } // handle()

    protected function checkMatrix($matrixKey,$requestAttrs,$r)
    {
        $isAllowed = null; // default: not set, may defer to other rule or lower priority rule if one is set

        if ( array_key_exists($matrixKey,$this->_accessMatrix) ) {

            if ( isset($this->_accessMatrix[$matrixKey][$r->name]) && (false===$this->_accessMatrix[$matrixKey][$r->name]) ) {

                // case: not a true empty, the permission is set to false
                $isAllowed = false; // set, will not check lower priority rules

            } else {

                // False case is covered above so now we can use 'empty' w/o worrying about losing the 'false' value...
                if ( empty($this->_accessMatrix[$matrixKey][$r->name]) ) {
    
                    $isAllowed = null; // not set, may defer to lower priority rule if one is set
    
                } else {
    
                    $accessCheckDelegate = $this->_accessMatrix[$matrixKey][$r->name]; // safe to access
                    if ( is_callable($accessCheckDelegate) ) {
                        // Callable delegate, returns boolean
                        $isAllowed = call_user_func_array($accessCheckDelegate,[$this->_sessionUser,$requestAttrs['routeparams'],$requestAttrs['queryparams']]);
                    } else {
                        $isAllowed = $accessCheckDelegate;
                    }
                }

            }
        }

        return $isAllowed;
    }
    
    // uses $this->_accessMatrix, // $this->_sessionUser
    protected function isAllowed($matchingRoutes,$requestAttrs) 
    {
        // HERE: determine if *any* role of this user allows access by its rules for this route

        $isAllowed = null;

//dd($this->_sessionUser->roles->pluck('name'));
        foreach ($this->_sessionUser->roles as $r) {

            if ( array_key_exists('exact',$matchingRoutes) ) {
                $isAllowed = $this->checkMatrix( $matchingRoutes['exact'], $requestAttrs, $r );
            } 

            // Check this clause if not yet set
            if ( is_null($isAllowed) && array_key_exists('wildcard_action',$matchingRoutes) ) {
                $isAllowed = $this->checkMatrix( $matchingRoutes['wildcard_action'], $requestAttrs, $r );
            }

            if ( true === $isAllowed ) {
                break; // found a role that allows access per rules
            }
        } // foreach($this->_sessionUser->roles)

        $isAllowed = is_null($isAllowed) ? false : $isAllowed;
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
