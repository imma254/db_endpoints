# Flask-API endpoints using databases
[![Build Status](https://travis-ci.org/imma254/API-endpoints.svg?branch=master)](https://travis-ci.org/imma254/API-endpoints) | <a href="//www.dmca.com/Protection/Status.aspx?ID=0e62a6b4-0fef-427f-816d-7fbc57964a14" title="DMCA.com Protection Status" class="dmca-badge"> <img src ="https://images.dmca.com/Badges/dmca_protected_sml_120m.png?ID=0e62a6b4-0fef-427f-816d-7fbc57964a14"  alt="DMCA.com Protection Status" /></a>  <script src="https://images.dmca.com/Badges/DMCABadgeHelper.min.js"> </script>

## Overview
Creation of the website's flask API endpoints.

## Description of Task to be completed? 
Setup API and test endpoints that do the following using data structures:
- Get all questions.
- Get a question.
- Post a question.
- Post an answer to a question.

#### *API endpoints overview*
Test | API-endpoint | HTTP-Verbs
------------ | ------- | -----
User can sign up | /auth/signup | POST
User can login | /auth/login | POST
User can post a question | /questions | POST							
User can view all questions | /questions | GET
User can view a single question | /questions/question_id | GET
User can view all answers | /questions/<question_id>/answers | GET
User can view a single answer | /questions/question_id/answer/<answer_id> | GET
User can edit a question	| /questions/question_id | PUT
User can delete a question	| /questions/question_id | DELETE
User can delete an answer| /questions/question_id/answers/<answer_id> | DELETE
User can up vote a question	| /questions/question_id/upvote | PUT
User can down vote a question	| /questions/question_id/upvote | PUT

## How should this manually be tested? 
- Navigate to the db-endpoints repository.
- Clone or download the repository
`$ git clone https://github.com/imma254/API-endpoints`
- Install and run virtualenv on your PC
`$ pip install virtualenv`
`$ virtualenv env`
- Activate virtualenv
`$ . env/Scripts/activate`
- Install Flask
`$ pip install Flask`
- Run the app
`$ python app.py`
- Test the app
`$ python test_app.py`

## Any background context you want to provide?
- PostgreSQL
- Flask

## Relevant Pivotal Tracker Stories
 - #159925230
