<?php
namespace App\Http\Middleware;

//use \App\Models\Enums\Permitapplication\PAstateEnum;

class CheckSiteRole extends AccessManager
{

    protected function getAccessMatrix() {
        $access_matrix = [

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
             'site.accounts.store'=>[
                 'newlogix-admin'=>'all',
                 'fielder'=>'all',
                 'project-manager'=>'all',
              ],
            'site.accounts.create'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.accounts.show'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.accounts.update'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.accounts.destroy'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.accounts.edit'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],

            'site.applications.index'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.store'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.attachPole'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.create'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.doAssignFielder'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.showAssignFielder'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.validateByField'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.update'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.show'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.applications.doAttachPole'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
             'site.applications.doAttachPole'=>[
                 'newlogix-admin'=>'all',
                 'fielder'=>'all',
                 'project-manager'=>'all',
              ],
            'site.applications.edit'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],

            'site.comments.store'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.comments.create'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],

            'site.mediafiles.store'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.mediafiles.create'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.mediafiles.download'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],

            'site.poles.index'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.match'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.show'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.update'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.destroy'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.create'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.edit'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],

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

            'site.poles.fieldCreate'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
            ],
            'site.poles.field'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],
            'site.poles.fieldEdit'=>[
                'newlogix-admin'=>'all',
                'fielder'=>'all',
                'project-manager'=>'all',
             ],




/*
            // agency.agencies.*
            'agency.agencies.index'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>'all',
                'department-admin'=>'all',
            ],
            'agency.agencies.show'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>function($user,$routeParams,$queryParams) {
                    $agency = \App\Models\Agency::findBySlug($routeParams['agency']);
                    $isAllowed = \App\Libs\AccessControl::isOrganizationMember($agency,$user);
                    return $isAllowed;
                },
                'department-admin'=>null,
            ],


            // agency.formcomponents.*
            'agency.formcomponents.index'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>'all',
                'department-admin'=>'all',
            ],
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
            'agency.formcomponents.create'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>'all',
                'department-admin'=>'all',
            ],
            'agency.formcomponents.edit'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>function($user,$routeParams,$queryParams) {
                    $agency = $user->ofAgency();
                    $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                    $isAllowed = \App\Libs\AccessControl::isOperationOnFormcomponentByOrganizationAllowed($formcomponent,$agency,'update');
                    return $isAllowed;
                },
                'department-admin'=>function($user,$routeParams,$queryParams) {
                    $department = $user->ofDepartment();
                    $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                    $isAllowed = \App\Libs\AccessControl::isOperationOnFormcomponentByOrganizationAllowed($formcomponent,$department,'update');
                    return $isAllowed;
                },
            ],
            'agency.formcomponents.clone'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>'all',
                'department-admin'=>'all',
            ],
            'agency.formcomponents.preview'=>[
                'newlogix-admin'=>'all',
                'agency-admin'=>function($user,$routeParams,$queryParams) {
                    $agency = $user->ofAgency();
                    $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                    $isAllowed = \App\Libs\AccessControl::isFormcomponentOwner($formcomponent,$agency);
                    return $isAllowed;
                },
                'department-admin'=>function($user,$routeParams,$queryParams) {
                    $department = $user->ofDepartment();
                    $formcomponent = \App\Models\Formcomponent::findBySlug($routeParams['formcomponent']);
                    $isAllowed = \App\Libs\AccessControl::isFormcomponentOwner($formcomponent,$department);
                    return $isAllowed;
                },
            ],
*/
        ];
      return $access_matrix;
    }
}
