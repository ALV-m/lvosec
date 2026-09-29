import { useState } from "react";
import type { FormEvent } from "react";
import { Redirect } from "wouter";
import { useAdminLogin } from "@workspace/api-client-react";
import { Lock, ShieldCheck } from "lucide-react";
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
import { useAdminAuth } from "@/lib/admin-auth";

function AdminLoginPage() {
  const { status, admin, refresh } = useAdminAuth();
  const loginMutation = useAdminLogin({
    mutation: {
      onSuccess: () => {
        void refresh();
        toast.success("Signed in to platform admin");
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  if (status === "authenticated" && admin) {
    return <Redirect to="/" replace />;
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!username.trim() || !password) {
      toast.error("Enter your username and password.");
      return;
    }
    loginMutation.mutate({ data: { username: username.trim(), password } });
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck className="size-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold">Platform Admin</h1>
            <p className="text-sm text-muted-foreground">
              LVO Security — owner access
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
            <CardDescription>
              Restricted to platform administrators.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="admin-username">Username</Label>
                <Input
                  id="admin-username"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="admin-password">Password</Label>
                <Input
                  id="admin-password"
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

export default AdminLoginPage;
