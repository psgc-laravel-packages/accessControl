<?php
namespace PsgcLaravelPackages\AccessControl;

use Closure;

abstract class AccessManager
{
    // %REQUIRES: User model implement ->roles attribute (eg, relations)
    // %REQUIRES: User model implement ->username // %TODO: make a function so it's generic returns some kind of GUID, or a GUID

    protected $_superadminRoles = []; // roles that override access matrix checking

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
            //\App::abort(403, 'Unauthorized action.');
            return \Redirect::route('login');
        }
        $this->setSuperadminRoles(); // must be first!!
        $sessionUser = \Auth::user();

        if ( $this->isSuperadmin($sessionUser) ) {

            $is = true;

        } else {

            // Not a super admin, so use access matrix
            $accessMatrix = $this->accessMatrix();

            // === Parse request ===

            $requestAttrs = [
                'routename'   => $request->route()->getName(),
                'routeparams' => $request->route()->parameters(),
                'queryparams' => $request->all(),
            ];
    
            $is = self::checkMatrix($accessMatrix, $requestAttrs, $sessionUser);
        }

        if (!$is) {
            $jsonStr = json_encode(['route'=>$requestAttrs['routename'],'user'=>$sessionUser->username,'roles'=>$sessionUser->roles]);
            \App::abort(403, 'Unauthorized action for role: '.$jsonStr);
        }

        return $next($request); // ...else allowed, return

    } // handle()

    
    // Use 'access matrix' to determine permission:
    //   ~ parse routename to find matches in matrix (including wildcards)
    //   ~ pass matching routes to isAllowed() method
    public static function checkMatrix(&$accessMatrix, $requestAttrs, $sessionUser) : ?bool
    {

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
        if ( array_key_exists($requestAttrs['routename'],$accessMatrix) ) {
            $matchingRoutes['exact'] = $requestAttrs['routename']; // exact match
        }
        $wildcardActionRoute = implode('.',[$routePrefix,$routeResource,'*']);
        if ( array_key_exists($wildcardActionRoute,$accessMatrix) ) {
            $matchingRoutes['wildcard_action'] = $wildcardActionRoute; // eg api.widgets.*
        }

        // === Do the check (set $is) ===
        $is = self::isAllowed($accessMatrix, $matchingRoutes,$requestAttrs, $sessionUser);

        return $is;

    } // checkMatrix()


    // Use 'access matrix' and any matching routes found to determine permission:
    //   ~ Iterate over all the user's roles
    //   ~ Each role is checked with matching rules/routes in order rule priority. If access is granted loop breaks.
    protected static function isAllowed(&$accessMatrix, $matchingRoutes,$requestAttrs,$sessionUser)  : ?bool
    {
        // HERE: determine if *any* role of this user allows access by its rules for this route

        $is = null;

        foreach ($sessionUser->roles as $r) {

            if ( array_key_exists('exact',$matchingRoutes) ) {
                $is = self::checkRule( $accessMatrix, $matchingRoutes['exact'], $requestAttrs, $r, $sessionUser );
            } 

            // Check this clause if not yet set
            if ( is_null($is) && array_key_exists('wildcard_action',$matchingRoutes) ) {
                $is = self::checkRule( $accessMatrix, $matchingRoutes['wildcard_action'], $requestAttrs, $r, $sessionUser );
            }

            if ( true === $is ) {
                break; // found a role that allows access per rules
            }
        } // foreach($sessionUser->roles)

        $is = is_null($is) ? false : $is;
        return $is;

    } // isAllowed()

    // Check an individual 'rule'
    //   ~ if false, deny access
    //   ~ else if true, allow accces
    //   ~ else if null or not set, defer
    protected static function checkRule(&$accessMatrix, $matrixKey,$requestAttrs,$r,$sessionUser) : ?bool
    {
        $is = null; // default: not set, may defer to other rule or lower priority rule if one is set

        if ( array_key_exists($matrixKey,$accessMatrix) ) {

            if ( isset($accessMatrix[$matrixKey][$r->name]) && (false===$accessMatrix[$matrixKey][$r->name]) ) {

                // case: not a true empty, the permission is set to false
                $is = false; // set, will not check lower priority rules

            } else {

                // False case is covered above so now we can use 'empty' w/o worrying about losing the 'false' value...
                if ( empty($accessMatrix[$matrixKey][$r->name]) ) {
    
                    $is = null; // not set, may defer to lower priority rule if one is set
    
                } else {
    
                    $accessCheckDelegate = $accessMatrix[$matrixKey][$r->name]; // safe to access
                    if ( is_callable($accessCheckDelegate) ) {
                        // Callable delegate, returns boolean
                        $is = call_user_func_array($accessCheckDelegate,[$sessionUser,$requestAttrs['routeparams'],$requestAttrs['queryparams']]);
                    } else {
                        $is = $accessCheckDelegate;
                    }
                }

            }
        }

        return $is;

    } // checkRule()

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
