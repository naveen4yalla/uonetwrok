<script>
  import { user } from './user';

  let username;
  let password;

  function login() {
    user.auth(username, password, ({ err }) => err && alert(err));
  }

  function signup() {
    user.create(username, password, ({ err }) => {
      if (err) {
        alert(err);
      } else {
        login();
      }
    });
  }
</script>

<label style="font-size:25px" for="username">Username</label>
<input placeholder="Enter the Username of UO App" name="username" bind:value={username} minlength="3" maxlength="16" />

<label style="font-size:25px" for="password">Password</label>
<input placeholder="Enter the Password" name="password" bind:value={password} type="password" />

<button style="background-color:#006ee6" class="login" on:click={login}>Login</button>
<button style="background-color:#006ee6" class="login"  on:click={signup}>Sign Up</button>
  
