## Build a Blog

The files create a blog that as per the directions for the Udacity's 3rd assignment'(build a portfolio site). 

### Prerequisite 

This assignment uses templates. Jinja2 and python2.7 were used to write the files.

### Description

The blog contains a header with four links: login, signup, logout, New Post.

The webiste uses 15 html page used for templates, a css file in the folder css, an svg file for the logo, a yaml file, and a python file.

The blog includes the following features:

- A login form  validates user input, and displays the error(s) when necessary. After a successful login, the user is directed to a welcome page.

- A front page that lists blog posts (accessible through the word "BLOG" in the top right corner or at the top of the content of each webpage.

- A form to submit new entries (via the link New Post in the header)
Blog posts have their own page (via permalink)

- A logout form validates user input, and displays the error(s) when necessary. After logging out, the cookie is cleared and the user is redirected to the Signup page.

- Users are able to edit/delete their posts. They receive an error message if they disobey this rule.

- Users can like/unlike posts, but not their own. They receive an error message if they disobey this rule.

- Users can comment on posts. They can only edit/delete their own posts, and they should receive an error message if they disobey this rule.


### User Registration
A Registration form validates user input, and displays the error(s) when necessary.
After a successful registration, a user is directed to a welcome page with a greeting, “Welcome, [User]” where [User] is a name set in a cookie.

If a user attempts to visit the welcome page without being signed in (without having a cookie), then he is redirected to the Signup page.

If a user attempts to sign up or login when already loggedin, a message will be displayed on the signup or login pages to inform the user that he is already logged in.

If a user attempts to write a new post (via the link New Post in the header) when not logged in, the user is sent to the login page.

### How to run the code

#### Access the application the Internet
The application is available at: 
https://rot13-147105.appspot.com/login

#### Run the code through Google AppEngine
The steps used to run the application are as follows.

1. Create a new Cloud Platform Console project or retrieve the project ID of an existing project from the Google Cloud Platform Console
2. Install the gcloud tool, you install and then initialize the Google Cloud SDK.
save the file in a dedicated directory
3. From within the dedicated directory, start the local development server with the following command:

```sh
dev_appserver.py .
```

The local development server will be running and listening for requests on port 8080.

4. Visit http://localhost:8080/ in your web browser to view the app.

5. To deploy your app to App Engine, run the following command from within the root directory of your application where the app.yaml file is located:
```sh
gcloud app deploy
```
6. To launch the browser and view the app at http://[YOUR_PROJECT_ID].appspot.com, run the following command:
```sh
gcloud app browse
```
steps 1 to 6 are detailed in the Google AppEngine documentation as per the following link:
https://cloud.google.com/appengine/docs/python/quickstart#prerequisites

**Author**

C. D. selected wrote the code for the html, css, and html pages.

**License**

The files are private domain works. The logo was provided by Pixabay (pixabay.com).

