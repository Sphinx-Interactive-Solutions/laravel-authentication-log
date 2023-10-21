<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\OtherDeviceLogout;

class OtherDeviceLogoutListener extends EventListener
{
    public function handle($event): void
    {
        if (! $this->isListenerForEvent($event, 'other-device-logout', OtherDeviceLogout::class)) {
            return;
        }

        if (! $this->isLoggable($event)) {
            return;
        }
        
        $listener = config('authentication-log.events.other-device-logout', OtherDeviceLogout::class);
        if (! $event instanceof $listener) {
            return;
        }

        if ($event->user) {
            $user = $event->user;
            $ip = $this->request->ip();
            $userAgent = $this->request->userAgent();
            $authenticationLog = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

            if (! $authenticationLog) {
                $authenticationLog = new AuthenticationLog([
                    'ip_address' => $ip,
                    'user_agent' => $userAgent,
                ]);
            }

            foreach ($user->authentications()->whereLoginSuccessful(true)->whereNull('logout_at')->get() as $log) {
                if ($log->id !== $authenticationLog->id) {
                    $log->update([
                        'cleared_by_user' => true,
                        'logout_at' => now(),
                    ]);
                }
            }
        }
    }
}
