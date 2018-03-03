# Access Control for use in Laravel Middleware

## Usage:

1. extend base class AccessManager...

2. Implement :

    abstract protected function getAccessMatrix()

3. Optional: override to set super admin roles:

    protected function setSuperadminRoles();
    {
        $this->_superadminRoles = ['super-admin'];
    }

## Example:

    use PsgcLaravelPackages\AccessControl\AccessManager;

    class CheckSiteRole extends AccessManager
    {

        protected function getAccessMatrix() {
        return [
    
                'site.dashboard.show'=>[
                    'newlogix-admin'=>'all',
                    'fielder'=>'all',
                    'project-manager'=>'all',
                ],
    
                'site.accounts.index'=>[
                    'newlogix-admin'=>'all',
                    'fielder'=>'all',
                    'project-manager'=>'all',
                ],
                ...
                'site.profiles.show'=>[
                    'newlogix-admin'=>'all',
                    'fielder'=>function($user,$routeParams,$queryParams) {
                        $user = \App\Models\User::findByUsername($routeParams['username']);
                        $isAllowed = ($user->id == $this->_sessionUser->id);
                        return $isAllowed;
                    },
                    'project-manager'=>function($user,$routeParams,$queryParams) {
                        $user = \App\Models\User::findByUsername($routeParams['username']);
                        $isAllowed = ($user->id == $this->_sessionUser->id);
                        return $isAllowed;
                    },
                ],
                ...
                'agency.formcomponents.show'=>[
                    'newlogix-admin'=>'all',
                    'agency-admin'=>function($user,$routeParams,$queryParams) {
                        $agency = $user->ofAgency();
                        $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                        $isAllowed = \App\Libs\AccessControl::isOperationOnFormcomponentByOrganizationAllowed($formcomponent,$agency,'read');
                        return $isAllowed;
                    },
                    'department-admin'=>function($user,$routeParams,$queryParams) {
                    $department = $user->ofDepartment();
                        $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                        $isAllowed = \App\Libs\AccessControl::isOperationOnFormcomponentByOrganizationAllowed($formcomponent,$department,'read');
                        return $isAllowed;
                    },
                ],
                ...
            ];
        }

Edit app/Http/Kernel.php to update route middleware:

    protected $routeMiddleware = [
        'auth' => \Illuminate\Auth\Middleware\Authenticate::class,
        ...

        'checksite' => \App\Http\Middleware\CheckSiteRole::class,
    ];


Add via middleware in routes file...: 

    Route::group(['middleware'=>['checksite'], 'as'=>'site.', 'namespace'=>'Site'], function()
    {
       ...
    });
