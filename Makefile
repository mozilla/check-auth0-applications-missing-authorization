STACK_NAME	:= CheckAuth0Apps
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.iam.mozilla.com
CODE_STORAGE_S3_PREFIX	:= check-auth0-applications-missing-authorization

.PHONE: deploy
deploy:
	./deploy.sh \
		 check-auth0-applications-missing-authorization.yml \
		 $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(STACK_NAME) \
		 $(CODE_STORAGE_S3_PREFIX)
