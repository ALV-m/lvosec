import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Redirect, useLocation } from "wouter";
import { useLogin, useLoginWithLink } from "@workspace/api-client-react";
import { Lock, Server } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { useAuth } from "@/lib/auth";
import { defaultPathFor } from "@/lib/submenus";

function LoginPage({ slug }: { slug?: string }) {
  const { status, user, refresh } = useAuth();
  const loginMutation = useLogin({
    slug,
    mutation: {
      onSuccess: () => {
        void refresh();
        toast.success("Signed in");
      },
      onError: (error) => toast.error(error.message),
    },
  });
  const loginLinkMutation = useLoginWithLink({
    slug,
    mutation: {
      onSuccess: () => {
        void refresh();
        toast.success("Signed in");
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const [, navigate] = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const link = params.get("link");
    if (!link) return;
    loginLinkMutation.mutate({ data: { link } });
    const clean = window.location.pathname;
    window.history.replaceState({}, "", clean);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (status === "authenticated" && user) {
    return (
      <Redirect to={defaultPathFor(user.role, user.submenuAccess)} replace />
    );
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!username.trim() || !password) {
      toast.error("Enter your username and password.");
      return;
    }
    loginMutation.mutate({ data: { username: username.trim(), password } });
  };

  if (loginLinkMutation.isPending) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <Spinner className="size-6" />
          <p className="text-sm">Signing you in…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Server className="size-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold">LVO Security</h1>
            <p className="text-sm text-muted-foreground">
              Computer Manager
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
            <CardDescription>
              Use your dashboard account to continue.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loginMutation.isPending}>
                {loginMutation.isPending ? (
                  <Spinner className="size-4" />
                ) : (
                  <Lock className="size-4" />
                )}
                Sign in
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default LoginPage;
